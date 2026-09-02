//! Windows named-pipe launcher-owned decision broker.

use std::{
    env,
    ffi::OsStr,
    io,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    ptr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
};

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;

use crate::{
    arming, audit,
    decision::{self, Decision, DecisionContext},
    process::{self, ProcessIdentity, ProcessReader, WinProcess},
    protocol::{self, HookInput},
};

pub const BROKER_PROTOCOL_VERSION: &str = "permission-binding-v1";
pub const MAX_BROKER_MESSAGE_BYTES: usize = protocol::MAX_INPUT_BYTES + 4096;
pub const MAX_BROKER_RESPONSE_BYTES: usize = 256;
pub const MAX_ACTIVE_CONNECTIONS: usize = 16;
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub codex_version: String,
    pub expected_cwd: PathBuf,
    pub expected_command: Option<String>,
    pub audit_path: Option<PathBuf>,
    pub verification_only: bool,
}

#[derive(Debug)]
pub struct Session {
    pipe_name: String,
    secret: String,
}

impl Session {
    pub fn create() -> Result<Self> {
        let mut random = [0_u8; 16];
        fill(&mut random).context("generate private broker pipe suffix")?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let pipe_name = format!(r"\\.\pipe\codex-autoapprover-{suffix}");
        let secret = arming::new_secret()?;
        Ok(Self { pipe_name, secret })
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn arm_child(&self, command: &mut std::process::Command) -> Result<()> {
        arming::arm_child(command, std::path::Path::new(&self.pipe_name), &self.secret)
    }

    pub fn cleanup(self) -> Result<()> {
        Ok(())
    }
}

struct SharedState {
    expected: RwLock<Option<ProcessIdentity>>,
    shutdown: AtomicBool,
    active_connections: AtomicUsize,
    config: BrokerConfig,
    session_secret: String,
    launcher_sid: String,
    pipe_name: String,
}

pub struct Broker {
    shared: Arc<SharedState>,
    join: Option<thread::JoinHandle<()>>,
}

impl Broker {
    pub fn start(session: &Session, config: BrokerConfig) -> Result<Self> {
        let launcher_sid = process::launcher_user_sid().context("read launcher user SID")?;
        let security = security::PipeSecurityAttributes::new(&launcher_sid)
            .context("build private broker pipe security descriptor")?;
        let pipe_handle = SendHandle(create_server_pipe(session.pipe_name(), &security)?);
        if pipe_handle.0 == INVALID_HANDLE_VALUE {
            bail!("create private broker named pipe")
        }

        let shared = Arc::new(SharedState {
            expected: RwLock::new(None),
            shutdown: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            config,
            session_secret: session.secret().to_owned(),
            launcher_sid,
            pipe_name: session.pipe_name().to_owned(),
        });
        let thread_state = Arc::clone(&shared);
        let join = thread::Builder::new()
            .name("codex-autoapprover-broker".into())
            .spawn(move || {
                let handle = pipe_handle.get();
                let security =
                    match security::PipeSecurityAttributes::new(&thread_state.launcher_sid) {
                        Ok(value) => value,
                        Err(_) => {
                            close_handle(handle);
                            return;
                        }
                    };
                serve(handle, thread_state, security);
            })
            .context("start broker thread")?;
        Ok(Self {
            shared,
            join: Some(join),
        })
    }

    pub fn set_codex_identity(&self, identity: ProcessIdentity) -> Result<()> {
        let mut expected = self
            .shared
            .expected
            .write()
            .map_err(|_| anyhow::anyhow!("broker identity state poisoned"))?;
        *expected = Some(identity);
        Ok(())
    }

    pub fn stop_accepting(&self) {
        self.shared.shutdown.store(true, Ordering::Release);
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.shared.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            join.join()
                .map_err(|_| anyhow::anyhow!("broker thread failed"))?;
        }
        Ok(())
    }
}

fn serve(
    initial_pipe: HANDLE,
    shared: Arc<SharedState>,
    security: security::PipeSecurityAttributes,
) {
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut pipe_handle = initial_pipe;
    while !shared.shutdown.load(Ordering::Acquire) {
        workers.retain(|worker| !worker.is_finished());
        for worker in workers.drain(..) {
            let _ = worker.join();
        }
        if shared.active_connections.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        let connected = unsafe { ConnectNamedPipe(pipe_handle, ptr::null_mut()) };
        let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if connected == 0
            && last_error != ERROR_PIPE_CONNECTED
            && shared.shutdown.load(Ordering::Acquire)
        {
            break;
        }
        if connected != 0 || last_error == ERROR_PIPE_CONNECTED {
            if shared.active_connections.fetch_add(1, Ordering::AcqRel) >= MAX_ACTIVE_CONNECTIONS {
                shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                close_handle(pipe_handle);
            } else {
                let client_pipe = SendHandle(pipe_handle);
                let worker_state = Arc::clone(&shared);
                workers.push(thread::spawn(move || {
                    handle_connection(client_pipe, &worker_state);
                    worker_state
                        .active_connections
                        .fetch_sub(1, Ordering::AcqRel);
                }));
            }
            pipe_handle = match create_server_pipe(&shared.pipe_name, &security) {
                Ok(handle) => handle,
                Err(_) => break,
            };
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
    close_handle(pipe_handle);
    for worker in workers {
        let _ = worker.join();
    }
}

fn create_server_pipe(
    pipe_name: &str,
    security: &security::PipeSecurityAttributes,
) -> Result<HANDLE> {
    let wide = encode_wide(pipe_name);
    let handle = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_ACTIVE_CONNECTIONS as u32,
            MAX_BROKER_MESSAGE_BYTES as u32,
            MAX_BROKER_RESPONSE_BYTES as u32,
            CONNECTION_TIMEOUT.as_millis() as u32,
            security.as_ptr(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("create private broker named pipe")
    }
    Ok(handle)
}

fn handle_connection(pipe: SendHandle, shared: &Arc<SharedState>) {
    let pipe = pipe.0;
    let mut client_pid = 0_u32;
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut client_pid) };
    if ok == 0 || client_pid == 0 {
        close_handle(pipe);
        return;
    }
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let frame = match read_frame_until(pipe, MAX_BROKER_MESSAGE_BYTES, deadline) {
        Ok(frame) => frame,
        Err(_) => {
            close_handle(pipe);
            return;
        }
    };
    if ensure_no_trailing_data(pipe, deadline).is_err() {
        let _ = write_response_until(pipe, BrokerDecision::NoDecision, deadline);
        close_handle(pipe);
        return;
    }
    let request = match parse_request(&frame) {
        Ok(request) => request,
        Err(_) => {
            let _ = write_response_until(pipe, BrokerDecision::NoDecision, deadline);
            close_handle(pipe);
            return;
        }
    };
    let reader = WinProcess;
    let peer_user_matches = process::peer_user_matches_launcher(client_pid, &shared.launcher_sid);
    let allowed = verify_request(shared, client_pid, &request, &reader, peer_user_matches);
    if allowed {
        if let Some(path) = shared.config.audit_path.as_deref()
            && (audit::hook_invoked_at(
                path,
                request.hook_input.tool_name.as_deref(),
                request.hook_input.hook_event_name.as_deref(),
            )
            .is_err()
                || audit::hook_allow_at(
                    path,
                    request.hook_input.tool_name.as_deref().unwrap_or("unknown"),
                    request.hook_input.tool_input.as_ref(),
                )
                .is_err())
        {
            let _ = write_response_until(pipe, BrokerDecision::NoDecision, deadline);
            close_handle(pipe);
            return;
        }
        let _ = write_response_until(pipe, BrokerDecision::Allow, deadline);
    } else {
        let _ = write_response_until(pipe, BrokerDecision::NoDecision, deadline);
    }
    unsafe {
        DisconnectNamedPipe(pipe);
    }
    close_handle(pipe);
}

#[derive(Debug, Deserialize)]
struct BrokerRequest {
    protocol_version: String,
    message_type: String,
    session_secret: String,
    hook_input: HookInput,
}

#[derive(Debug, Serialize, Deserialize)]
struct BrokerResponse {
    protocol_version: String,
    message_type: String,
    decision: String,
}

#[derive(Clone, Copy)]
enum BrokerDecision {
    Allow,
    NoDecision,
}

fn verify_request(
    shared: &Arc<SharedState>,
    peer_pid: u32,
    request: &BrokerRequest,
    reader: &impl ProcessReader,
    peer_user_matches_launcher: bool,
) -> bool {
    let Some(expected) = shared.expected.read().ok().and_then(|value| value.clone()) else {
        return false;
    };
    if shared.shutdown.load(Ordering::Acquire)
        || !peer_user_matches_launcher
        || !arming::valid_token(Some(&request.session_secret))
        || !constant_time_equal(&request.session_secret, &shared.session_secret)
        || !validate_peer(reader, peer_pid, expected.clone())
    {
        return false;
    }
    let expected_cwd = shared.config.expected_cwd.to_string_lossy();
    let context = DecisionContext {
        codex_version: &shared.config.codex_version,
        expected_cwd: expected_cwd.as_ref(),
        expected_command: shared.config.expected_command.as_deref(),
        verification_only: shared.config.verification_only,
    };
    matches!(
        decision::decide(&request.hook_input, context),
        Decision::Allow
    ) && !shared.shutdown.load(Ordering::Acquire)
        && validate_peer(reader, peer_pid, expected)
}

fn validate_peer(reader: &impl ProcessReader, peer_pid: u32, expected: ProcessIdentity) -> bool {
    peer_pid > 0 && process::validate_ancestry(reader, peer_pid, expected).is_ok()
}

fn parse_request(bytes: &[u8]) -> Result<BrokerRequest> {
    if bytes.len() > MAX_BROKER_MESSAGE_BYTES {
        bail!("broker request too large")
    }
    let value = protocol::parse_unique_object(bytes).map_err(|error| anyhow::anyhow!(error))?;
    let object = value
        .as_object()
        .context("broker request is not an object")?;
    const FIELDS: &[&str] = &[
        "protocol_version",
        "message_type",
        "session_secret",
        "hook_input",
    ];
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        bail!("broker request has unexpected fields")
    }
    let request: BrokerRequest = serde_json::from_value(value).context("decode broker request")?;
    if request.protocol_version != BROKER_PROTOCOL_VERSION
        || request.message_type != "permission_request"
    {
        bail!("unsupported broker request")
    }
    Ok(request)
}

fn parse_response(bytes: &[u8]) -> Result<bool> {
    let value = protocol::parse_unique_object(bytes).map_err(|error| anyhow::anyhow!(error))?;
    let object = value
        .as_object()
        .context("broker response is not an object")?;
    const FIELDS: &[&str] = &["protocol_version", "message_type", "decision"];
    if object.len() != FIELDS.len() || object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        bail!("broker response has unexpected fields")
    }
    let response: BrokerResponse = serde_json::from_value(value)?;
    if response.protocol_version != BROKER_PROTOCOL_VERSION || response.message_type != "decision" {
        bail!("unsupported broker response")
    }
    match response.decision.as_str() {
        "allow" => Ok(true),
        "no_decision" => Ok(false),
        _ => bail!("invalid broker decision"),
    }
}

pub fn request(input: &HookInput) -> Result<bool> {
    let pipe_name =
        env::var_os(arming::SESSION_SOCKET_ENV).context("broker socket is not armed")?;
    let secret = env::var(arming::SESSION_TOKEN_ENV).context("session secret is not armed")?;
    if !arming::valid_token(Some(&secret))
        || env::var(arming::PROTOCOL_ENV).ok().as_deref() != Some(arming::PROTOCOL_VERSION)
    {
        bail!("invalid hook arming")
    }
    let wide = encode_wide(OsStr::new(&pipe_name));
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!("connect to broker")
    }
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let request = serde_json::json!({
        "protocol_version": BROKER_PROTOCOL_VERSION,
        "message_type": "permission_request",
        "session_secret": secret,
        "hook_input": input,
    });
    let bytes = serde_json::to_vec(&request)?;
    let result = (|| -> io::Result<bool> {
        write_frame_until(handle, &bytes, MAX_BROKER_MESSAGE_BYTES, deadline)?;
        let response = read_frame_until(handle, MAX_BROKER_RESPONSE_BYTES, deadline)?;
        ensure_no_trailing_data(handle, deadline)?;
        parse_response(&response).map_err(io::Error::other)
    })();
    close_handle(handle);
    result.map_err(Into::into)
}

pub fn constant_time_equal(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.as_bytes()
        .iter()
        .zip(right.as_bytes())
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn read_frame_until(handle: HANDLE, maximum: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact_until(handle, &mut header, deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_exact_until(handle, &mut bytes, deadline)?;
    Ok(bytes)
}

fn write_frame_until(
    handle: HANDLE,
    bytes: &[u8],
    maximum: usize,
    deadline: Instant,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid frame length",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    write_all_until(handle, &length.to_be_bytes(), deadline)?;
    write_all_until(handle, bytes, deadline)
}

fn ensure_no_trailing_data(handle: HANDLE, deadline: Instant) -> io::Result<()> {
    let mut byte = [0_u8; 1];
    match read_exact_until(handle, &mut byte, deadline) {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Ok(()) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing broker data",
        )),
        Err(error) => Err(error),
    }
}

fn write_response_until(
    handle: HANDLE,
    decision: BrokerDecision,
    deadline: Instant,
) -> io::Result<()> {
    let response = BrokerResponse {
        protocol_version: BROKER_PROTOCOL_VERSION.into(),
        message_type: "decision".into(),
        decision: match decision {
            BrokerDecision::Allow => "allow",
            BrokerDecision::NoDecision => "no_decision",
        }
        .into(),
    };
    let bytes = serde_json::to_vec(&response).map_err(io::Error::other)?;
    write_frame_until(handle, &bytes, MAX_BROKER_RESPONSE_BYTES, deadline)
}

fn read_exact_until(handle: HANDLE, buffer: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker decision timed out",
            ));
        }
        wait_for_readable(handle, deadline)?;
        let mut read = 0_u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer[offset..].as_mut_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 && read == 0 {
            return Err(io::Error::last_os_error());
        }
        offset += read as usize;
    }
    Ok(())
}

fn write_all_until(handle: HANDLE, buffer: &[u8], deadline: Instant) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker decision timed out",
            ));
        }
        let mut written = 0_u32;
        let ok = unsafe {
            WriteFile(
                handle,
                buffer[offset..].as_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 && written == 0 {
            return Err(io::Error::last_os_error());
        }
        offset += written as usize;
    }
    Ok(())
}

fn wait_for_readable(handle: HANDLE, deadline: Instant) -> io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker decision timed out",
            ));
        }
        let mut available = 0_u32;
        let ok = unsafe {
            PeekNamedPipe(
                handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        };
        if ok != 0 && available > 0 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn close_handle(handle: HANDLE) {
    if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
        unsafe { CloseHandle(handle) };
    }
}

fn encode_wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

struct SendHandle(HANDLE);

// HANDLE values are kernel-owned tokens safe to move between threads when
// lifetimes are bounded by the spawning broker worker.
unsafe impl Send for SendHandle {}

impl SendHandle {
    fn get(self) -> HANDLE {
        self.0
    }
}

mod security {
    use super::encode_wide;
    use anyhow::Result;
    use std::ptr;
    use windows_sys::Win32::Foundation::{GENERIC_ALL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, EXPLICIT_ACCESS_W, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
        TRUSTEE_IS_USER,
    };
    use windows_sys::Win32::Security::{
        ACL, InitializeSecurityDescriptor, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    // `descriptor` and `acl` are kept alive while `attributes` references the descriptor.
    #[allow(dead_code)]
    pub struct PipeSecurityAttributes {
        descriptor: SECURITY_DESCRIPTOR,
        acl: Vec<u8>,
        sid: *mut std::ffi::c_void,
        attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    }

    impl PipeSecurityAttributes {
        pub fn new(launcher_sid: &str) -> Result<Self> {
            let mut sid = ptr::null_mut();
            let wide = encode_wide(launcher_sid);
            let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
            if ok == 0 || sid.is_null() {
                anyhow::bail!("convert launcher SID for broker pipe DACL")
            }
            let mut descriptor = unsafe { std::mem::zeroed::<SECURITY_DESCRIPTOR>() };
            let ok = unsafe {
                InitializeSecurityDescriptor(
                    &mut descriptor as *mut _ as *mut _,
                    SECURITY_DESCRIPTOR_REVISION,
                )
            };
            if ok == 0 {
                unsafe { LocalFree(sid.cast()) };
                anyhow::bail!("initialize broker pipe security descriptor")
            }
            let acl = build_dacl(sid)?;
            let ok = unsafe {
                SetSecurityDescriptorDacl(
                    &mut descriptor as *mut _ as *mut _,
                    1,
                    acl.as_ptr() as *mut ACL,
                    0,
                )
            };
            if ok == 0 {
                unsafe { LocalFree(sid.cast()) };
                anyhow::bail!("set broker pipe security descriptor DACL")
            }
            let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: &mut descriptor as *mut _ as *mut _,
                bInheritHandle: 0,
            };
            Ok(Self {
                descriptor,
                acl,
                sid,
                attributes,
            })
        }

        pub fn as_ptr(&self) -> *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            &self.attributes as *const _ as *mut _
        }
    }

    impl Drop for PipeSecurityAttributes {
        fn drop(&mut self) {
            if !self.sid.is_null() {
                unsafe { LocalFree(self.sid.cast()) };
            }
        }
    }

    fn build_dacl(sid: *mut std::ffi::c_void) -> Result<Vec<u8>> {
        let explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL,
            grfAccessMode: SET_ACCESS,
            grfInheritance: windows_sys::Win32::Security::NO_INHERITANCE,
            Trustee: windows_sys::Win32::Security::Authorization::TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation:
                    windows_sys::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid.cast(),
            },
        };
        let mut acl = ptr::null_mut();
        let ok = unsafe { SetEntriesInAclW(1, &explicit, ptr::null_mut(), &mut acl) };
        if ok != 0 || acl.is_null() {
            anyhow::bail!("build broker pipe ACL")
        }
        let acl_size = unsafe { (*(acl as *const ACL)).AclSize } as usize;
        let mut bytes = vec![0_u8; acl_size];
        unsafe {
            ptr::copy_nonoverlapping(acl as *const u8, bytes.as_mut_ptr(), acl_size);
            LocalFree(acl.cast());
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_comparison_requires_equal_secret() {
        assert!(constant_time_equal("abcd", "abcd"));
        assert!(!constant_time_equal("abcd", "abce"));
    }
}
