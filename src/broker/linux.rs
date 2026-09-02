//! Linux-only launcher-owned decision broker.
//!
//! The hook is an untrusted client. The broker is the only component that can
//! turn a PermissionRequest into an allow response.

use std::{
    env, fs,
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use rustix::{net::sockopt::socket_peercred, process::geteuid};
use serde::{Deserialize, Serialize};
use tempfile::{Builder, TempDir};

use crate::{
    arming, audit,
    decision::{self, Decision, DecisionContext},
    process::{self, ProcFs, ProcessIdentity, ProcessReader},
    protocol::{self, HookInput},
};

pub const BROKER_PROTOCOL_VERSION: &str = "permission-binding-v1";
pub const MAX_BROKER_MESSAGE_BYTES: usize = protocol::MAX_INPUT_BYTES + 4096;
pub const MAX_BROKER_RESPONSE_BYTES: usize = 256;
pub const MAX_ACTIVE_CONNECTIONS: usize = 16;
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
pub const MAX_RUNTIME_SOCKET_PATH_BYTES: usize = 100;

#[derive(Debug)]
pub struct Session {
    runtime: TempDir,
    socket_path: PathBuf,
    secret: String,
}

impl Session {
    pub fn create() -> Result<Self> {
        let runtime = create_private_runtime_directory()?;
        let socket_path = runtime.path().join("broker.sock");
        if socket_path.as_os_str().as_bytes().len() > MAX_RUNTIME_SOCKET_PATH_BYTES {
            let _ = runtime.close();
            bail!("private broker socket path is too long")
        }
        if fs::symlink_metadata(&socket_path).is_ok() {
            let _ = runtime.close();
            bail!("refusing a reused broker socket path")
        }
        let secret = arming::new_secret()?;
        Ok(Self {
            runtime,
            socket_path,
            secret,
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn secret(&self) -> &str {
        &self.secret
    }

    pub fn arm_child(&self, command: &mut std::process::Command) -> Result<()> {
        arming::arm_child(command, &self.socket_path, &self.secret)
    }

    pub fn cleanup(self) -> Result<()> {
        remove_socket_safely(&self.socket_path)?;
        self.runtime
            .close()
            .context("remove private broker runtime directory")
    }
}

pub fn validate_runtime_dir(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect XDG_RUNTIME_DIR {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.uid() != geteuid().as_raw() {
        bail!("XDG_RUNTIME_DIR is not a directory owned by the effective user")
    }
    if metadata.mode() & 0o777 != 0o700 {
        bail!("XDG_RUNTIME_DIR must have mode 0700")
    }
    Ok(())
}

fn create_private_runtime_directory() -> Result<TempDir> {
    if let Some(path) = env::var_os("XDG_RUNTIME_DIR") {
        let path = PathBuf::from(path);
        if validate_runtime_dir(&path).is_ok()
            && let Ok(directory) = private_tempdir_in(&path)
        {
            return Ok(directory);
        }
    }
    private_tempdir_in(&env::temp_dir())
}

fn private_tempdir_in(parent: &Path) -> Result<TempDir> {
    let directory = Builder::new()
        .prefix(".codex-autoapprover-")
        .tempdir_in(parent)
        .context("create private broker runtime directory")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .context("protect private broker runtime directory")?;
    validate_private_directory(directory.path())?;
    let probe_path = directory.path().join("socket-probe");
    let probe = UnixListener::bind(&probe_path).context("probe private broker socket support")?;
    drop(probe);
    fs::remove_file(probe_path).context("remove private broker socket probe")?;
    Ok(directory)
}

fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).context("inspect private broker runtime directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("private broker runtime directory has unsafe ownership or permissions")
    }
    Ok(())
}

fn remove_socket_safely(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket()
                || metadata.uid() != geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o600
            {
                bail!("refusing to remove an unsafe broker socket replacement")
            }
            fs::remove_file(path).context("remove broker socket")?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect broker socket during cleanup"),
    }
}

#[derive(Debug, Clone)]
pub struct BrokerConfig {
    pub codex_version: String,
    pub expected_cwd: PathBuf,
    pub expected_command: Option<String>,
    pub audit_path: Option<PathBuf>,
    pub verification_only: bool,
}

struct SharedState {
    expected: RwLock<Option<ProcessIdentity>>,
    shutdown: AtomicBool,
    active_connections: AtomicUsize,
    config: BrokerConfig,
    session_secret: String,
}

pub struct Broker {
    shared: Arc<SharedState>,
    join: Option<thread::JoinHandle<()>>,
}

impl Broker {
    pub fn start(session: &Session, config: BrokerConfig) -> Result<Self> {
        let listener =
            UnixListener::bind(session.socket_path()).context("bind private broker Unix socket")?;
        if let Err(error) =
            fs::set_permissions(session.socket_path(), fs::Permissions::from_mode(0o600))
                .context("protect private broker Unix socket")
                .and_then(|()| validate_socket(session.socket_path()))
                .and_then(|()| {
                    listener
                        .set_nonblocking(true)
                        .context("configure broker listener")
                })
        {
            drop(listener);
            let _ = remove_socket_safely(session.socket_path());
            return Err(error);
        }

        let shared = Arc::new(SharedState {
            expected: RwLock::new(None),
            shutdown: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            config,
            session_secret: session.secret().to_owned(),
        });
        let thread_state = Arc::clone(&shared);
        let join = match thread::Builder::new()
            .name("codex-autoapprover-broker".into())
            .spawn(move || serve(listener, thread_state))
            .context("start broker thread")
        {
            Ok(join) => join,
            Err(error) => {
                let _ = remove_socket_safely(session.socket_path());
                return Err(error);
            }
        };
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

fn serve(listener: UnixListener, shared: Arc<SharedState>) {
    let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
    while !shared.shutdown.load(Ordering::Acquire) {
        let mut remaining = Vec::with_capacity(workers.len());
        for worker in workers.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                remaining.push(worker);
            }
        }
        workers = remaining;
        if shared.active_connections.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if shared.active_connections.fetch_add(1, Ordering::AcqRel)
                    >= MAX_ACTIVE_CONNECTIONS
                {
                    shared.active_connections.fetch_sub(1, Ordering::AcqRel);
                    continue;
                }
                let worker_state = Arc::clone(&shared);
                workers.push(thread::spawn(move || {
                    handle_connection(stream, &worker_state);
                    worker_state
                        .active_connections
                        .fetch_sub(1, Ordering::AcqRel);
                }));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    drop(listener);
    for worker in workers {
        let _ = worker.join();
    }
}

fn handle_connection(mut stream: UnixStream, shared: &SharedState) {
    let _ = stream.set_read_timeout(Some(CONNECTION_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECTION_TIMEOUT));
    let Some(credentials) = peer_credentials(&stream) else {
        return;
    };
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    let Ok(frame) = read_frame_until(&mut stream, MAX_BROKER_MESSAGE_BYTES, deadline) else {
        return;
    };
    if ensure_no_trailing_data(&mut stream, deadline).is_err() {
        let _ = write_response_until(&mut stream, BrokerDecision::NoDecision, deadline);
        return;
    }
    let request = match parse_request(&frame) {
        Ok(request) => request,
        Err(_error) => {
            let _ = write_response_until(&mut stream, BrokerDecision::NoDecision, deadline);
            return;
        }
    };
    let proc_reader = ProcFs;
    let allowed = verify_request(shared, credentials, &request, &proc_reader);
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
            let _ = write_response_until(&mut stream, BrokerDecision::NoDecision, deadline);
            return;
        }
        let _ = write_response_until(&mut stream, BrokerDecision::Allow, deadline);
    } else {
        let _ = write_response_until(&mut stream, BrokerDecision::NoDecision, deadline);
    }
}

#[derive(Clone, Copy)]
struct PeerCredentials {
    pid: u32,
    uid: u32,
    _gid: u32,
}

fn peer_credentials(stream: &UnixStream) -> Option<PeerCredentials> {
    let credentials = socket_peercred(stream).ok()?;
    Some(PeerCredentials {
        pid: credentials.pid.as_raw_pid() as u32,
        uid: credentials.uid.as_raw(),
        _gid: credentials.gid.as_raw(),
    })
}

fn validate_peer(
    reader: &impl ProcessReader,
    peer_pid: u32,
    expected: ProcessIdentity,
    effective_uid: u32,
) -> bool {
    peer_pid > 0
        && expected.effective_uid == effective_uid
        && process::validate_ancestry(reader, peer_pid, expected).is_ok()
}

fn peer_uid_matches(credentials: Option<PeerCredentials>, effective_uid: u32) -> bool {
    credentials.is_some_and(|credentials| credentials.uid == effective_uid)
}

fn verify_request(
    shared: &SharedState,
    credentials: PeerCredentials,
    request: &BrokerRequest,
    reader: &impl ProcessReader,
) -> bool {
    let Some(expected) = shared.expected.read().ok().and_then(|value| *value) else {
        return false;
    };
    let effective_uid = geteuid().as_raw();
    if shared.shutdown.load(Ordering::Acquire)
        || !peer_uid_matches(Some(credentials), effective_uid)
        || !arming::valid_token(Some(&request.session_secret))
        || !constant_time_equal(&request.session_secret, &shared.session_secret)
        || !validate_peer(reader, credentials.pid, expected, effective_uid)
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
        && validate_peer(reader, credentials.pid, expected, effective_uid)
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

fn write_response_until(
    stream: &mut UnixStream,
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
    write_frame_until(stream, &bytes, MAX_BROKER_RESPONSE_BYTES, deadline)
}

#[allow(dead_code)]
fn read_frame(stream: &mut UnixStream, maximum: usize) -> io::Result<Vec<u8>> {
    read_frame_until(stream, maximum, Instant::now() + CONNECTION_TIMEOUT)
}

fn read_frame_until(
    stream: &mut UnixStream,
    maximum: usize,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

#[allow(dead_code)]
fn write_frame(stream: &mut UnixStream, bytes: &[u8], maximum: usize) -> io::Result<()> {
    write_frame_until(stream, bytes, maximum, Instant::now() + CONNECTION_TIMEOUT)
}

fn write_frame_until(
    stream: &mut UnixStream,
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
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(&length.to_be_bytes())?;
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(bytes)?;
    stream.flush()
}

fn ensure_no_trailing_data(stream: &mut UnixStream, deadline: Instant) -> io::Result<()> {
    stream.set_read_timeout(Some(remaining(deadline)?))?;
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte)? {
        0 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing broker data",
        )),
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "broker decision timed out",
        ))
    } else {
        Ok(duration)
    }
}

pub fn request(input: &HookInput) -> Result<bool> {
    let socket = env::var_os(arming::SESSION_SOCKET_ENV).context("broker socket is not armed")?;
    let secret = env::var(arming::SESSION_TOKEN_ENV).context("session secret is not armed")?;
    if !arming::valid_token(Some(&secret))
        || env::var(arming::PROTOCOL_ENV).ok().as_deref() != Some(arming::PROTOCOL_VERSION)
    {
        bail!("invalid hook arming")
    }
    let mut stream = UnixStream::connect(PathBuf::from(socket)).context("connect to broker")?;
    stream.set_read_timeout(Some(CONNECTION_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_TIMEOUT))?;
    let request = serde_json::json!({
        "protocol_version": BROKER_PROTOCOL_VERSION,
        "message_type": "permission_request",
        "session_secret": secret,
        "hook_input": input,
    });
    let bytes = serde_json::to_vec(&request)?;
    let deadline = Instant::now() + CONNECTION_TIMEOUT;
    write_frame_until(&mut stream, &bytes, MAX_BROKER_MESSAGE_BYTES, deadline)?;
    stream.shutdown(Shutdown::Write)?;
    let response = read_frame_until(&mut stream, MAX_BROKER_RESPONSE_BYTES, deadline)?;
    ensure_no_trailing_data(&mut stream, deadline)?;
    parse_response(&response)
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

fn validate_socket(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect broker socket")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("broker socket has unsafe type, owner, or permissions")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeProc {
        records: HashMap<u32, process::ProcessRecord>,
    }

    impl ProcessReader for FakeProc {
        fn read_process(&self, pid: u32) -> Result<process::ProcessRecord, process::ProcessError> {
            self.records
                .get(&pid)
                .copied()
                .ok_or(process::ProcessError::Unavailable)
        }
    }

    fn fixture_request(secret: &str) -> BrokerRequest {
        parse_request(
            &serde_json::to_vec(&serde_json::json!({
                "protocol_version": BROKER_PROTOCOL_VERSION,
                "message_type": "permission_request",
                "session_secret": secret,
                "hook_input": {
                    "session_id":"s",
                    "cwd":"/tmp/work",
                    "hook_event_name":"PermissionRequest",
                    "tool_name":"Bash",
                    "tool_input":{"command":"printf synthetic"}
                }
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn shared(secret: &str, expected: process::ProcessIdentity) -> SharedState {
        SharedState {
            expected: RwLock::new(Some(expected)),
            shutdown: AtomicBool::new(false),
            active_connections: AtomicUsize::new(0),
            config: BrokerConfig {
                codex_version: "0.151.0".into(),
                expected_cwd: "/tmp/work".into(),
                expected_command: None,
                audit_path: None,
                verification_only: false,
            },
            session_secret: secret.into(),
        }
    }

    #[test]
    fn constant_time_comparison_requires_equal_secret() {
        assert!(constant_time_equal("abcd", "abcd"));
        assert!(!constant_time_equal("abcd", "abce"));
        assert!(!constant_time_equal("abcd", "abc"));
    }

    #[test]
    fn broker_protocol_rejects_wrong_version_and_extra_fields() {
        let base = serde_json::json!({
            "protocol_version": BROKER_PROTOCOL_VERSION,
            "message_type": "permission_request",
            "session_secret": "a".repeat(64),
            "hook_input": {"hook_event_name":"PermissionRequest"}
        });
        assert!(parse_request(serde_json::to_vec(&base).unwrap().as_slice()).is_ok());
        let mut wrong = base.clone();
        wrong["protocol_version"] = serde_json::json!("permission-binding-v0");
        assert!(parse_request(serde_json::to_vec(&wrong).unwrap().as_slice()).is_err());
        let extra = serde_json::json!({"protocol_version":BROKER_PROTOCOL_VERSION,"message_type":"permission_request","session_secret":"a".repeat(64),"hook_input":{},"extra":true});
        assert!(parse_request(serde_json::to_vec(&extra).unwrap().as_slice()).is_err());
    }

    #[test]
    fn valid_secret_and_exact_ancestry_are_required_for_allow() {
        let secret = "a".repeat(64);
        let pid = std::process::id();
        let identity = process::ProcessIdentity {
            pid,
            start_time: 7,
            effective_uid: geteuid().as_raw(),
        };
        let reader = FakeProc {
            records: HashMap::from([(
                pid,
                process::ProcessRecord {
                    identity,
                    parent_pid: 1,
                },
            )]),
        };
        let state = shared(&secret, identity);
        let credentials = PeerCredentials {
            pid,
            uid: geteuid().as_raw(),
            _gid: 0,
        };
        assert!(verify_request(
            &state,
            credentials,
            &fixture_request(&secret),
            &reader
        ));
        assert!(!verify_request(
            &state,
            credentials,
            &fixture_request(&"b".repeat(64)),
            &reader
        ));
        assert!(!verify_request(
            &state,
            PeerCredentials {
                uid: 9999,
                ..credentials
            },
            &fixture_request(&secret),
            &reader
        ));
        assert!(!verify_request(
            &state,
            credentials,
            &fixture_request(&secret),
            &FakeProc {
                records: HashMap::new()
            }
        ));
    }

    #[test]
    fn stale_or_shutdown_brokers_cannot_decide() {
        let secret = "a".repeat(64);
        let pid = std::process::id();
        let identity = process::ProcessIdentity {
            pid,
            start_time: 7,
            effective_uid: geteuid().as_raw(),
        };
        let reader = FakeProc {
            records: HashMap::from([(
                pid,
                process::ProcessRecord {
                    identity,
                    parent_pid: 1,
                },
            )]),
        };
        let state = shared(&secret, identity);
        state.shutdown.store(true, Ordering::Release);
        assert!(!verify_request(
            &state,
            PeerCredentials {
                pid,
                uid: geteuid().as_raw(),
                _gid: 0
            },
            &fixture_request(&secret),
            &reader
        ));
    }

    #[test]
    fn missing_peer_credentials_cannot_match() {
        assert!(!peer_uid_matches(None, geteuid().as_raw()));
    }

    #[test]
    fn response_parser_rejects_trailing_and_ambiguous_decisions() {
        let good = serde_json::json!({"protocol_version":BROKER_PROTOCOL_VERSION,"message_type":"decision","decision":"allow"});
        assert!(parse_response(&serde_json::to_vec(&good).unwrap()).unwrap());
        assert!(parse_response(b"{\"protocol_version\":\"permission-binding-v1\",\"message_type\":\"decision\",\"decision\":\"allow\"} trailing").is_err());
        assert!(parse_response(b"{\"protocol_version\":\"permission-binding-v1\",\"message_type\":\"decision\",\"decision\":\"allow\" ,\"decision\":\"no_decision\"}").is_err());
    }

    #[test]
    fn runtime_validation_rejects_unsafe_directory() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_runtime_dir(directory.path()).is_err());
        let link = directory.path().with_extension("link");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(validate_runtime_dir(&link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_refuses_symlink_and_non_socket_replacements() {
        let directory = tempfile::tempdir().unwrap();
        let regular = directory.path().join("regular");
        fs::write(&regular, b"not a socket").unwrap();
        assert!(remove_socket_safely(&regular).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(remove_socket_safely(&link).is_err());
        assert!(regular.exists());
        assert!(link.exists());
    }

    #[test]
    fn frames_reject_oversized_and_truncated_messages() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&(MAX_BROKER_MESSAGE_BYTES as u32 + 1).to_be_bytes())
            .unwrap();
        assert!(read_frame(&mut reader, MAX_BROKER_MESSAGE_BYTES).is_err());

        writer.write_all(&10_u32.to_be_bytes()).unwrap();
        writer.write_all(b"short").unwrap();
        drop(writer);
        assert!(read_frame(&mut reader, MAX_BROKER_MESSAGE_BYTES).is_err());
        assert!(write_frame(&mut reader, b"", MAX_BROKER_RESPONSE_BYTES).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_broker_handles_sequential_and_concurrent_requests() {
        use std::sync::{Mutex, OnceLock};

        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let session = Session::create().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let broker = Broker::start(
            &session,
            BrokerConfig {
                codex_version: "0.151.0".into(),
                expected_cwd: cwd.clone(),
                expected_command: None,
                audit_path: None,
                verification_only: false,
            },
        )
        .unwrap();
        let runtime_metadata = fs::symlink_metadata(session.runtime.path()).unwrap();
        assert_eq!(runtime_metadata.mode() & 0o777, 0o700);
        let socket_metadata = fs::symlink_metadata(session.socket_path()).unwrap();
        assert!(socket_metadata.file_type().is_socket());
        assert_eq!(socket_metadata.mode() & 0o777, 0o600);
        let identity = process::current_process_identity(std::process::id()).unwrap();
        broker.set_codex_identity(identity).unwrap();
        unsafe {
            env::set_var(arming::SESSION_SOCKET_ENV, session.socket_path());
            env::set_var(arming::SESSION_TOKEN_ENV, session.secret());
            env::set_var(arming::PROTOCOL_ENV, arming::PROTOCOL_VERSION);
        }
        let input = protocol::parse(
            format!(
                r#"{{"session_id":"s","cwd":"{}","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{{"command":"printf synthetic"}}}}"#,
                cwd.display()
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(request(&input).unwrap());
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let input = protocol::parse(
                    format!(
                        r#"{{"session_id":"s","cwd":"{}","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{{"command":"printf synthetic"}}}}"#,
                        cwd.display()
                    )
                    .as_bytes(),
                )
                .unwrap();
                thread::spawn(move || request(&input).unwrap())
            })
            .collect();
        assert!(threads.into_iter().all(|thread| thread.join().unwrap()));
        unsafe { env::set_var(arming::SESSION_TOKEN_ENV, "b".repeat(64)) };
        assert!(!request(&input).unwrap());
        unsafe {
            env::remove_var(arming::SESSION_SOCKET_ENV);
            env::remove_var(arming::SESSION_TOKEN_ENV);
            env::remove_var(arming::PROTOCOL_ENV);
        }
        broker.shutdown().unwrap();
        let path = session.socket_path().to_path_buf();
        session.cleanup().unwrap();
        assert!(!path.exists());
    }
}
