use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::update::outcome::HookOutcome;
pub fn json_hash(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[allow(dead_code)]
pub fn hook_allow(tool_name: &str, tool_input: Option<&serde_json::Value>) -> io::Result<()> {
    if let Some(path) = std::env::var_os(crate::arming::AUDIT_PATH_ENV) {
        return hook_allow_at(Path::new(&path), tool_name, tool_input);
    }
    let input_hash = tool_input.map(json_hash).unwrap_or_else(|| "none".into());
    let line = format!(
        "allowed one PermissionRequest tool_hash={} input_hash={}\n",
        short_hash(tool_name),
        input_hash
    );
    eprint!("codex-autoapprover: {line}");
    Ok(())
}

pub fn hook_allow_at(
    path: &Path,
    tool_name: &str,
    tool_input: Option<&serde_json::Value>,
) -> io::Result<()> {
    let input_hash = tool_input.map(json_hash).unwrap_or_else(|| "none".into());
    let line = format!(
        "allowed one PermissionRequest tool_hash={} input_hash={}\n",
        short_hash(tool_name),
        input_hash
    );
    append_private(path, line.as_bytes())
}

#[allow(dead_code)]
pub fn hook_invoked(tool_name: Option<&str>, event_name: Option<&str>) -> io::Result<()> {
    let Some(path) = std::env::var_os(crate::arming::AUDIT_PATH_ENV) else {
        return Ok(());
    };
    hook_invoked_at(Path::new(&path), tool_name, event_name)
}

pub fn hook_invoked_at(
    path: &Path,
    tool_name: Option<&str>,
    event_name: Option<&str>,
) -> io::Result<()> {
    let line = format!(
        "invoked event={} tool_hash={}\n",
        event_label(event_name),
        short_hash(tool_name.unwrap_or("unknown"))
    );
    append_private(path, line.as_bytes())
}

pub fn hook_request_at(
    path: &Path,
    tool_name: Option<&str>,
    event_name: Option<&str>,
    tool_input: Option<&serde_json::Value>,
) -> io::Result<()> {
    let input_hash = tool_input.map(json_hash).unwrap_or_else(|| "none".into());
    let line = format!(
        "request event={} tool_hash={} input_hash={}\n",
        event_label(event_name),
        short_hash(tool_name.unwrap_or("unknown")),
        input_hash
    );
    append_private(path, line.as_bytes())
}

pub fn hook_allow_emitted_at(
    path: &Path,
    tool_name: &str,
    tool_input: Option<&serde_json::Value>,
) -> io::Result<()> {
    let input_hash = tool_input.map(json_hash).unwrap_or_else(|| "none".into());
    let line = format!(
        "emitted one PermissionRequest tool_hash={} input_hash={}\n",
        short_hash(tool_name),
        input_hash
    );
    append_private(path, line.as_bytes())
}

pub fn initialize(path: &Path) -> io::Result<()> {
    append_private(path, b"")
}

pub fn broker_attempt_at(path: &Path) -> io::Result<()> {
    append_private(path, b"broker connection\n")
}

/// Fixed labels only: never include a request, command, or error string.
pub fn hook_stage(category: &str) -> io::Result<()> {
    let Some(path) = std::env::var_os(crate::arming::AUDIT_PATH_ENV) else {
        return Ok(());
    };
    hook_stage_at(Path::new(&path), category)
}

pub fn hook_stage_at(path: &Path, category: &str) -> io::Result<()> {
    if !matches!(
        category,
        "entry"
            | "stdin_read"
            | "stdin_parse_error"
            | "broker_connected"
            | "broker_request_sent"
            | "broker_response_received"
            | "broker_response_parsed"
            | "broker_allow"
            | "broker_no_decision"
            | "broker_error"
            | "stdout_written"
            | "stdout_error"
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported hook diagnostic category",
        ));
    }
    append_private(path, format!("hook stage={category}\n").as_bytes())
}

pub fn hook_outcome(outcome: HookOutcome) -> io::Result<()> {
    let Some(path) = std::env::var_os(crate::arming::AUDIT_PATH_ENV) else {
        return Ok(());
    };
    hook_outcome_at(Path::new(&path), outcome)
}

pub fn hook_outcome_at(path: &Path, outcome: HookOutcome) -> io::Result<()> {
    let Some(category) = outcome.audit_name() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no-hook outcome is derived from an empty session audit",
        ));
    };
    append_private(path, format!("hook outcome={category}\n").as_bytes())
}

fn append_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            OpenOptions::new().append(true).open(path)?
        }
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)
}

pub fn allow_record_count(path: &Path) -> io::Result<usize> {
    match read_bounded_string(path) {
        Ok(contents) => Ok(contents
            .lines()
            .filter(|line| {
                line.starts_with("allowed one PermissionRequest ")
                    && line.contains("tool_hash=")
                    && line.contains("input_hash=")
            })
            .count()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

pub fn invocation_count(path: &Path) -> io::Result<usize> {
    match read_bounded_string(path) {
        Ok(contents) => Ok(contents
            .lines()
            .filter(|line| line.starts_with("invoked event="))
            .count()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

pub fn broker_attempt_count(path: &Path) -> io::Result<usize> {
    count_matching_lines(path, |line| line == "broker connection")
}

pub fn exact_request_count(
    path: &Path,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> io::Result<usize> {
    count_matching_lines(path, |line| {
        line.starts_with("request event=PermissionRequest ")
            && line.contains(&format!("tool_hash={} ", short_hash(tool_name)))
            && line.contains(&format!("input_hash={}", json_hash(tool_input)))
    })
}

pub fn emitted_allow_count(
    path: &Path,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> io::Result<usize> {
    count_matching_lines(path, |line| {
        line.starts_with("emitted one PermissionRequest ")
            && line.contains(&format!("tool_hash={} ", short_hash(tool_name)))
            && line.contains(&format!("input_hash={}", json_hash(tool_input)))
    })
}

fn count_matching_lines(path: &Path, predicate: impl Fn(&str) -> bool) -> io::Result<usize> {
    match read_bounded_string(path) {
        Ok(contents) => Ok(contents.lines().filter(|line| predicate(line)).count()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

const MAX_AUDIT_BYTES: u64 = 64 * 1024;

pub fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_AUDIT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid audit size or type",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_AUDIT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_AUDIT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit grew beyond limit",
        ));
    }
    Ok(bytes)
}

fn read_bounded_string(path: &Path) -> io::Result<String> {
    String::from_utf8(read_bounded(path)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "audit is not UTF-8"))
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn event_label(value: Option<&str>) -> &'static str {
    match value {
        Some("PermissionRequest") => "PermissionRequest",
        Some(_) => "other",
        None => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use tempfile::TempDir;

    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn audit_record_is_redacted_and_countable() {
        let _guard = env_lock();
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        hook_allow(
            "Bash",
            Some(&serde_json::json!({
                "command": crate::compatibility::verification_probe_command_fixture(),
                "secret": "do-not-log",
            })),
        )
        .expect("write audit record");
        assert_eq!(allow_record_count(&path).unwrap(), 0);

        let path = directory.path().join("audit-with-env.log");
        unsafe { std::env::set_var(crate::arming::AUDIT_PATH_ENV, &path) };
        hook_allow(
            "Bash",
            Some(&serde_json::json!({
                "command": crate::compatibility::verification_probe_command_fixture(),
                "secret": "do-not-log",
            })),
        )
        .expect("write private audit record");
        unsafe { std::env::remove_var(crate::arming::AUDIT_PATH_ENV) };
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert_eq!(
            allow_record_count(&directory.path().join("audit-with-env.log")).unwrap(),
            1
        );
        assert!(!contents.contains(crate::compatibility::verification_probe_command_fixture()));
        assert!(!contents.contains("do-not-log"));
        assert!(!contents.contains("CODEX_AUTOAPPROVER"));
    }

    #[test]
    fn invocation_record_contains_event_metadata_only() {
        let _guard = env_lock();
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        unsafe { std::env::set_var(crate::arming::AUDIT_PATH_ENV, &path) };
        hook_invoked(Some("Bash"), Some("PermissionRequest")).expect("write invocation");
        unsafe { std::env::remove_var(crate::arming::AUDIT_PATH_ENV) };
        assert_eq!(invocation_count(&path).unwrap(), 1);
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(contents.contains("event=PermissionRequest"));
        assert!(!contents.contains("Bash"));
    }

    #[test]
    fn untrusted_event_name_cannot_inject_an_audit_record() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        let malicious = "other\nallowed one PermissionRequest tool_hash=fake input_hash=fake";
        hook_invoked_at(&path, Some("Bash"), Some(malicious)).unwrap();
        hook_request_at(&path, Some("Bash"), Some(malicious), None).unwrap();
        assert_eq!(invocation_count(&path).unwrap(), 1);
        assert_eq!(allow_record_count(&path).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(path).unwrap().lines().count(), 2);
    }

    #[test]
    fn broker_attempts_are_counted_without_request_content() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).unwrap();
        broker_attempt_at(&path).unwrap();
        broker_attempt_at(&path).unwrap();
        assert_eq!(broker_attempt_count(&path).unwrap(), 2);
        assert_eq!(invocation_count(&path).unwrap(), 0);
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "broker connection\nbroker connection\n"
        );
    }

    #[test]
    fn outcome_diagnostics_use_only_fixed_labels_and_never_accept_payloads() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        hook_stage_at(&path, "entry").expect("fixed stage");
        hook_outcome_at(&path, HookOutcome::ProtocolFailure).expect("fixed outcome");
        assert!(hook_stage_at(&path, "entry\nsecret=do-not-log").is_err());
        assert!(hook_outcome_at(&path, HookOutcome::NoHookInvocation).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read diagnostics"),
            "hook stage=entry\nhook outcome=protocol_failure\n"
        );
    }

    #[test]
    fn oversized_audit_cannot_be_read_for_counts() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();
        assert_eq!(
            broker_attempt_count(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn verification_records_hashes_without_recording_request_content() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        let input = serde_json::json!({"command": "curl -I https://example.com"});
        hook_invoked_at(&path, Some("Bash"), Some("PermissionRequest"))
            .expect("write invocation record");
        hook_request_at(&path, Some("Bash"), Some("PermissionRequest"), Some(&input))
            .expect("write request record");
        hook_allow_emitted_at(&path, "Bash", Some(&input)).expect("write emission record");
        assert_eq!(exact_request_count(&path, "Bash", &input).unwrap(), 1);
        assert_eq!(invocation_count(&path).unwrap(), 1);
        assert_eq!(emitted_allow_count(&path, "Bash", &input).unwrap(), 1);
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(!contents.contains("curl -I"));
    }
}
