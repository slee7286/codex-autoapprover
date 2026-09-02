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
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

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
    launcher_sid: Vec<u8>,
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
        match wait_for_connection(pipe_handle, &shared.shutdown) {
            Ok(true) => {
                if shared.active_connections.fetch_add(1, Ordering::AcqRel)
                    >= MAX_ACTIVE_CONNECTIONS
                {
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
            }
            Ok(false) | Err(_) => break,
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
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_ACTIVE_CONNECTIONS as u32,
            MAX_BROKER_MESSAGE_BYTES as u32,
            MAX_BROKER_RESPONSE_BYTES as u32,
            CONNECTION_TIMEOUT.as_millis() as u32,
            security.as_ptr(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        bail!(
            "create private broker named pipe: {}",
            io::Error::last_os_error()
        )
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
    let frame = match read_frame_until(
        pipe,
        MAX_BROKER_MESSAGE_BYTES,
        deadline,
        Some(&shared.shutdown),
    ) {
        Ok(frame) => frame,
        Err(_) => {
            close_handle(pipe);
            return;
        }
    };
    if ensure_no_trailing_data(pipe).is_err() {
        let _ = write_response_until(
            pipe,
            BrokerDecision::NoDecision,
            deadline,
            Some(&shared.shutdown),
        );
        close_handle(pipe);
        return;
    }
    let request = match parse_request(&frame) {
        Ok(request) => request,
        Err(_) => {
            let _ = write_response_until(
                pipe,
                BrokerDecision::NoDecision,
                deadline,
                Some(&shared.shutdown),
            );
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
            let _ = write_response_until(
                pipe,
                BrokerDecision::NoDecision,
                deadline,
                Some(&shared.shutdown),
            );
            close_handle(pipe);
            return;
        }
        let _ = write_response_until(
            pipe,
            BrokerDecision::Allow,
            deadline,
            Some(&shared.shutdown),
        );
    } else {
        let _ = write_response_until(
            pipe,
            BrokerDecision::NoDecision,
            deadline,
            Some(&shared.shutdown),
        );
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
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let handle = connect_client(&wide, deadline).context("connect to broker")?;
    let request = serde_json::json!({
        "protocol_version": BROKER_PROTOCOL_VERSION,
        "message_type": "permission_request",
        "session_secret": secret,
        "hook_input": input,
    });
    let bytes = serde_json::to_vec(&request)?;
    let result = (|| -> io::Result<bool> {
        write_frame_until(handle, &bytes, MAX_BROKER_MESSAGE_BYTES, deadline, None)?;
        let response = read_frame_until(handle, MAX_BROKER_RESPONSE_BYTES, deadline, None)?;
        ensure_no_trailing_data(handle)?;
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

fn wait_for_connection(handle: HANDLE, shutdown: &AtomicBool) -> io::Result<bool> {
    let mut operation = OverlappedOperation::new()?;
    let connected = unsafe { ConnectNamedPipe(handle, &mut operation.overlapped) };
    if connected != 0 {
        return Ok(true);
    }
    let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if error == ERROR_PIPE_CONNECTED {
        return Ok(true);
    }
    if error != ERROR_IO_PENDING {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    loop {
        if shutdown.load(Ordering::Acquire) {
            operation.cancel(handle);
            return Ok(false);
        }
        let result = unsafe { WaitForSingleObject(operation.event, 50) };
        if result == WAIT_OBJECT_0 {
            let mut transferred = 0_u32;
            let ok =
                unsafe { GetOverlappedResult(handle, &operation.overlapped, &mut transferred, 0) };
            if ok != 0
                || unsafe { windows_sys::Win32::Foundation::GetLastError() } == ERROR_PIPE_CONNECTED
            {
                return Ok(true);
            }
            return Err(io::Error::last_os_error());
        }
        if result == WAIT_TIMEOUT {
            continue;
        }
        if result == WAIT_FAILED {
            operation.cancel(handle);
            return Err(io::Error::last_os_error());
        }
        return Err(io::Error::other("unexpected named-pipe wait result"));
    }
}

fn connect_client(pipe_name: &[u16], deadline: Instant) -> io::Result<HANDLE> {
    loop {
        let handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(handle);
        }
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if error != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "broker connection timed out",
            ));
        }
        let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let ok = unsafe { WaitNamedPipeW(pipe_name.as_ptr(), wait_ms) };
        if ok == 0 {
            let wait_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if wait_error == ERROR_PIPE_BUSY {
                continue;
            }
            return Err(io::Error::from_raw_os_error(wait_error as i32));
        }
    }
}

fn read_frame_until(
    handle: HANDLE,
    maximum: usize,
    deadline: Instant,
    shutdown: Option<&AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    read_exact_until(handle, &mut header, deadline, shutdown)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut bytes = vec![0_u8; length];
    read_exact_until(handle, &mut bytes, deadline, shutdown)?;
    Ok(bytes)
}

fn write_frame_until(
    handle: HANDLE,
    bytes: &[u8],
    maximum: usize,
    deadline: Instant,
    shutdown: Option<&AtomicBool>,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid frame length",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    write_all_until(handle, &length.to_be_bytes(), deadline, shutdown)?;
    write_all_until(handle, bytes, deadline, shutdown)
}

fn ensure_no_trailing_data(handle: HANDLE) -> io::Result<()> {
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
    if ok == 0 {
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if error == ERROR_BROKEN_PIPE {
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    if available > 0 {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing broker data",
        ))
    } else {
        Ok(())
    }
}

fn write_response_until(
    handle: HANDLE,
    decision: BrokerDecision,
    deadline: Instant,
    shutdown: Option<&AtomicBool>,
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
    write_frame_until(
        handle,
        &bytes,
        MAX_BROKER_RESPONSE_BYTES,
        deadline,
        shutdown,
    )
}

fn read_exact_until(
    handle: HANDLE,
    buffer: &mut [u8],
    deadline: Instant,
    shutdown: Option<&AtomicBool>,
) -> io::Result<()> {
    let mut offset = 0;
    let mut operation = OverlappedOperation::new()?;
    while offset < buffer.len() {
        let mut transferred = 0_u32;
        let read = unsafe {
            ResetEvent(operation.event);
            ReadFile(
                handle,
                buffer[offset..].as_mut_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut transferred,
                &mut operation.overlapped,
            )
        };
        let read = if read != 0 {
            transferred
        } else {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(if error == ERROR_BROKEN_PIPE {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "broker peer disconnected")
                } else {
                    io::Error::from_raw_os_error(error as i32)
                });
            }
            operation.complete(handle, deadline, shutdown)?
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "broker peer returned an empty read",
            ));
        }
        offset += read as usize;
    }
    Ok(())
}

fn write_all_until(
    handle: HANDLE,
    buffer: &[u8],
    deadline: Instant,
    shutdown: Option<&AtomicBool>,
) -> io::Result<()> {
    let mut offset = 0;
    let mut operation = OverlappedOperation::new()?;
    while offset < buffer.len() {
        let mut transferred = 0_u32;
        let written = unsafe {
            ResetEvent(operation.event);
            WriteFile(
                handle,
                buffer[offset..].as_ptr().cast(),
                (buffer.len() - offset) as u32,
                &mut transferred,
                &mut operation.overlapped,
            )
        };
        let written = if written != 0 {
            transferred
        } else {
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(if error == ERROR_BROKEN_PIPE {
                    io::Error::new(io::ErrorKind::BrokenPipe, "broker peer disconnected")
                } else {
                    io::Error::from_raw_os_error(error as i32)
                });
            }
            operation.complete(handle, deadline, shutdown)?
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "broker write returned zero bytes",
            ));
        }
        offset += written as usize;
    }
    Ok(())
}

struct OverlappedOperation {
    event: HANDLE,
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            event,
            overlapped: OVERLAPPED {
                hEvent: event,
                ..unsafe { std::mem::zeroed() }
            },
        })
    }

    fn complete(
        &mut self,
        handle: HANDLE,
        deadline: Instant,
        shutdown: Option<&AtomicBool>,
    ) -> io::Result<u32> {
        loop {
            if shutdown.is_some_and(|flag| flag.load(Ordering::Acquire)) {
                self.cancel(handle);
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "broker operation cancelled during shutdown",
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cancel(handle);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "broker decision timed out",
                ));
            }
            let wait_ms = remaining.as_millis().clamp(1, 50) as u32;
            let result = unsafe { WaitForSingleObject(self.event, wait_ms) };
            if result == WAIT_OBJECT_0 {
                let mut transferred = 0_u32;
                let ok =
                    unsafe { GetOverlappedResult(handle, &self.overlapped, &mut transferred, 0) };
                if ok != 0 {
                    return Ok(transferred);
                }
                let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                return Err(if error == ERROR_OPERATION_ABORTED {
                    io::Error::new(io::ErrorKind::Interrupted, "broker operation cancelled")
                } else if error == ERROR_BROKEN_PIPE {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "broker peer disconnected")
                } else {
                    io::Error::from_raw_os_error(error as i32)
                });
            }
            if result == WAIT_TIMEOUT {
                continue;
            }
            if result == WAIT_FAILED {
                self.cancel(handle);
                return Err(io::Error::last_os_error());
            }
            self.cancel(handle);
            return Err(io::Error::other("unexpected overlapped I/O wait result"));
        }
    }

    fn cancel(&mut self, handle: HANDLE) {
        unsafe {
            CancelIoEx(handle, &self.overlapped);
            let mut transferred = 0_u32;
            GetOverlappedResult(handle, &self.overlapped, &mut transferred, 1);
        }
    }
}

impl Drop for OverlappedOperation {
    fn drop(&mut self) {
        if !self.event.is_null() {
            unsafe { CloseHandle(self.event) };
        }
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
    use anyhow::Result;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, SET_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    };
    use windows_sys::Win32::Security::{
        ACL, InitializeSecurityDescriptor, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl,
    };

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    // The boxed descriptor stays at a stable address while `attributes` references it.
    #[allow(dead_code)]
    pub struct PipeSecurityAttributes {
        descriptor: Box<SECURITY_DESCRIPTOR>,
        acl: *mut ACL,
        sid: Vec<u8>,
        attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    }

    impl PipeSecurityAttributes {
        pub fn new(launcher_sid: &[u8]) -> Result<Self> {
            if !crate::process::sid_is_valid(launcher_sid) {
                anyhow::bail!("invalid launcher SID for broker pipe DACL")
            }
            let mut descriptor = Box::new(unsafe { std::mem::zeroed::<SECURITY_DESCRIPTOR>() });
            let ok = unsafe {
                InitializeSecurityDescriptor(
                    descriptor.as_mut() as *mut _ as *mut _,
                    SECURITY_DESCRIPTOR_REVISION,
                )
            };
            if ok == 0 {
                anyhow::bail!("initialize broker pipe security descriptor")
            }
            let acl = build_dacl(launcher_sid)?;
            let ok = unsafe {
                SetSecurityDescriptorDacl(descriptor.as_mut() as *mut _ as *mut _, 1, acl, 0)
            };
            if ok == 0 {
                unsafe { LocalFree(acl.cast()) };
                anyhow::bail!("set broker pipe security descriptor DACL")
            }
            let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: descriptor.as_mut() as *mut _ as *mut _,
                bInheritHandle: 0,
            };
            Ok(Self {
                descriptor,
                acl,
                sid: launcher_sid.to_vec(),
                attributes,
            })
        }

        pub fn as_ptr(&self) -> *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            &self.attributes as *const _ as *mut _
        }
    }

    impl Drop for PipeSecurityAttributes {
        fn drop(&mut self) {
            if !self.acl.is_null() {
                unsafe { LocalFree(self.acl.cast()) };
            }
        }
    }

    fn build_dacl(sid: &[u8]) -> Result<*mut ACL> {
        let explicit = EXPLICIT_ACCESS_W {
            grfAccessPermissions: windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE,
            grfAccessMode: SET_ACCESS,
            grfInheritance: windows_sys::Win32::Security::NO_INHERITANCE,
            Trustee: windows_sys::Win32::Security::Authorization::TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation:
                    windows_sys::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: sid.as_ptr().cast_mut().cast(),
            },
        };
        let mut acl = ptr::null_mut();
        let ok = unsafe { SetEntriesInAclW(1, &explicit, ptr::null_mut(), &mut acl) };
        if ok != 0 || acl.is_null() {
            anyhow::bail!("build broker pipe ACL")
        }
        Ok(acl)
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

    #[test]
    fn pipe_security_rejects_malformed_sid_and_accepts_current_user_sid() {
        assert!(security::PipeSecurityAttributes::new(&[]).is_err());
        let sid = process::launcher_user_sid().expect("current user SID");
        let attributes = security::PipeSecurityAttributes::new(&sid).expect("current-user DACL");
        assert!(!attributes.as_ptr().is_null());
    }

    fn test_broker() -> (Session, Broker) {
        let session = Session::create().expect("session");
        let broker = Broker::start(
            &session,
            BrokerConfig {
                codex_version: "0.152.1".into(),
                expected_cwd: std::env::current_dir().expect("cwd"),
                expected_command: None,
                audit_path: None,
                verification_only: true,
            },
        )
        .expect("broker");
        (session, broker)
    }

    #[test]
    fn broker_shutdown_cancels_an_idle_overlapped_accept() {
        let (session, broker) = test_broker();
        let started = Instant::now();
        broker.shutdown().expect("shutdown broker");
        assert!(started.elapsed() < Duration::from_secs(1));
        session.cleanup().expect("cleanup session");
    }

    #[test]
    fn blocked_named_pipe_read_is_cancelled_during_shutdown() {
        let (session, broker) = test_broker();
        let wide = encode_wide(OsStr::new(session.pipe_name()));
        let client = connect_client(&wide, Instant::now() + CONNECTION_TIMEOUT).expect("client");
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        broker.shutdown().expect("shutdown broker");
        assert!(started.elapsed() < Duration::from_secs(1));
        close_handle(client);
        session.cleanup().expect("cleanup session");
    }

    #[test]
    fn client_disconnect_does_not_leave_a_broker_worker_blocked() {
        let (session, broker) = test_broker();
        let wide = encode_wide(OsStr::new(session.pipe_name()));
        let client = connect_client(&wide, Instant::now() + CONNECTION_TIMEOUT).expect("client");
        thread::sleep(Duration::from_millis(50));
        close_handle(client);
        thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        broker.shutdown().expect("shutdown broker");
        assert!(started.elapsed() < Duration::from_secs(1));
        session.cleanup().expect("cleanup session");
    }

    #[test]
    fn partial_frame_read_has_a_bounded_deadline() {
        let (session, broker) = test_broker();
        let wide = encode_wide(OsStr::new(session.pipe_name()));
        let client = connect_client(&wide, Instant::now() + CONNECTION_TIMEOUT).expect("client");
        thread::sleep(Duration::from_millis(50));
        write_all_until(client, &[0_u8], Instant::now() + CONNECTION_TIMEOUT, None)
            .expect("write partial frame");
        let started = Instant::now();
        let error = read_frame_until(
            client,
            MAX_BROKER_MESSAGE_BYTES,
            Instant::now() + Duration::from_millis(100),
            None,
        )
        .expect_err("partial frame must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        close_handle(client);
        broker.shutdown().expect("shutdown broker");
        session.cleanup().expect("cleanup session");
    }
}
