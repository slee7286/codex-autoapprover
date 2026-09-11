use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

use crate::update::outcome::HookOutcome;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionCategory {
    RequestTrailingData,
    RequestSchema,
    CodexIdentity,
    Shutdown,
    PeerIdentity,
    SessionToken,
    SessionSecret,
    Ancestry,
    Version,
    Cwd,
    Tool,
    Schema,
    ExactCommand,
    AuditSink,
    PostValidationShutdown,
    PostValidationAncestry,
}

impl RejectionCategory {
    const ALL: &'static [Self] = &[
        Self::RequestTrailingData,
        Self::RequestSchema,
        Self::CodexIdentity,
        Self::Shutdown,
        Self::PeerIdentity,
        Self::SessionToken,
        Self::SessionSecret,
        Self::Ancestry,
        Self::Version,
        Self::Cwd,
        Self::Tool,
        Self::Schema,
        Self::ExactCommand,
        Self::AuditSink,
        Self::PostValidationShutdown,
        Self::PostValidationAncestry,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::RequestTrailingData => "request_trailing_data",
            Self::RequestSchema => "request_schema",
            Self::CodexIdentity => "codex_identity",
            Self::Shutdown => "shutdown",
            Self::PeerIdentity => "peer_identity",
            Self::SessionToken => "session_token",
            Self::SessionSecret => "session_secret",
            Self::Ancestry => "ancestry",
            Self::Version => "version",
            Self::Cwd => "cwd",
            Self::Tool => "tool",
            Self::Schema => "schema",
            Self::ExactCommand => "exact_command",
            Self::AuditSink => "audit_sink",
            Self::PostValidationShutdown => "post_validation_shutdown",
            Self::PostValidationAncestry => "post_validation_ancestry",
        }
    }
}

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
        event_name.unwrap_or("unknown"),
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
        "request event={} tool_hash={} input_hash={} command_hash={}\n",
        event_name.unwrap_or("unknown"),
        short_hash(tool_name.unwrap_or("unknown")),
        input_hash,
        command_hash(tool_input)
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
        "emitted one PermissionRequest tool_hash={} input_hash={} command_hash={}\n",
        short_hash(tool_name),
        input_hash,
        command_hash(tool_input)
    );
    append_private(path, line.as_bytes())
}

pub fn initialize(path: &Path) -> io::Result<()> {
    append_private(path, b"")
}

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
            | "stdin_parsed"
            | "stdin_parse_error"
            | "arming_valid"
            | "arming_invalid"
            | "broker_request"
            | "broker_connected"
            | "broker_request_sent"
            | "broker_response_received"
            | "broker_response_parsed"
            | "broker_server_connected"
            | "broker_server_request_received"
            | "broker_server_response_written"
            | "broker_server_response_acknowledged"
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
    let line = format!("hook stage={category}\n");
    append_private(path, line.as_bytes())
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

#[cfg(any(test, windows))]
pub fn hook_rejection_at(path: &Path, category: RejectionCategory) -> io::Result<()> {
    let line = format!("hook rejection={}\n", category.as_str());
    append_private(path, line.as_bytes())
}

#[cfg(any(test, windows))]
pub fn hook_exact_command_mismatch_at(
    path: &Path,
    expected: &str,
    actual: Option<&str>,
) -> io::Result<()> {
    let equal = actual.is_some_and(|value| value == expected);
    let line = format!(
        "hook exact_command expected_len={} actual_len={} actual_present={} equal={} leading_ws={} trailing_ws={} cr={} lf={} wrapper={}\n",
        expected.len(),
        actual.map_or(0, str::len),
        usize::from(actual.is_some()),
        usize::from(equal),
        usize::from(
            actual.is_some_and(|value| { value.chars().next().is_some_and(char::is_whitespace) })
        ),
        usize::from(
            actual.is_some_and(|value| {
                value.chars().next_back().is_some_and(char::is_whitespace)
            })
        ),
        usize::from(actual.is_some_and(|value| value.contains('\r'))),
        usize::from(actual.is_some_and(|value| value.contains('\n'))),
        actual.map_or("none", recognized_command_wrapper),
    );
    append_private(path, line.as_bytes())
}

pub fn hook_diagnostic_summary(path: &Path) -> io::Result<String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error),
    };
    let count = |category: &str| {
        contents
            .lines()
            .filter(|line| *line == format!("hook stage={category}"))
            .count()
    };
    let rejection_count = |category: RejectionCategory| {
        contents
            .lines()
            .filter(|line| *line == format!("hook rejection={}", category.as_str()))
            .count()
    };
    let first_rejection = contents
        .lines()
        .filter_map(|line| line.strip_prefix("hook rejection="))
        .find(|value| {
            RejectionCategory::ALL
                .iter()
                .any(|category| category.as_str() == *value)
        })
        .unwrap_or("none");
    let validated_request_count = contents
        .lines()
        .filter(|line| line.starts_with("request event=PermissionRequest "))
        .count();
    let exact_command_diagnostics = contents
        .lines()
        .filter_map(parse_exact_command_diagnostic)
        .collect::<Vec<_>>();
    let first_exact_command_diagnostic = exact_command_diagnostics
        .first()
        .map(String::as_str)
        .unwrap_or("none");
    Ok(format!(
        "verification diagnostics: hook stages entry={} stdin_read={} stdin_parsed={} stdin_parse_error={} arming_valid={} arming_invalid={} broker_request={} broker_connected={} broker_request_sent={} broker_response_received={} broker_response_parsed={} broker_server_connected={} broker_server_request_received={} broker_server_response_written={} broker_server_response_acknowledged={} broker_allow={} broker_no_decision={} broker_error={} stdout_written={} stdout_error={} validated_request={} first_broker_rejection={} exact_command_diagnostics={} first_exact_command_diagnostic={} rejection_counts request_trailing_data={} request_schema={} codex_identity={} shutdown={} peer_identity={} session_token={} session_secret={} ancestry={} version={} cwd={} tool={} schema={} exact_command={} audit_sink={} post_validation_shutdown={} post_validation_ancestry={}",
        count("entry"),
        count("stdin_read"),
        count("stdin_parsed"),
        count("stdin_parse_error"),
        count("arming_valid"),
        count("arming_invalid"),
        count("broker_request"),
        count("broker_connected"),
        count("broker_request_sent"),
        count("broker_response_received"),
        count("broker_response_parsed"),
        count("broker_server_connected"),
        count("broker_server_request_received"),
        count("broker_server_response_written"),
        count("broker_server_response_acknowledged"),
        count("broker_allow"),
        count("broker_no_decision"),
        count("broker_error"),
        count("stdout_written"),
        count("stdout_error"),
        validated_request_count,
        first_rejection,
        exact_command_diagnostics.len(),
        first_exact_command_diagnostic,
        rejection_count(RejectionCategory::RequestTrailingData),
        rejection_count(RejectionCategory::RequestSchema),
        rejection_count(RejectionCategory::CodexIdentity),
        rejection_count(RejectionCategory::Shutdown),
        rejection_count(RejectionCategory::PeerIdentity),
        rejection_count(RejectionCategory::SessionToken),
        rejection_count(RejectionCategory::SessionSecret),
        rejection_count(RejectionCategory::Ancestry),
        rejection_count(RejectionCategory::Version),
        rejection_count(RejectionCategory::Cwd),
        rejection_count(RejectionCategory::Tool),
        rejection_count(RejectionCategory::Schema),
        rejection_count(RejectionCategory::ExactCommand),
        rejection_count(RejectionCategory::AuditSink),
        rejection_count(RejectionCategory::PostValidationShutdown),
        rejection_count(RejectionCategory::PostValidationAncestry),
    ))
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
    match std::fs::read_to_string(path) {
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

/// Count executable-entry stage records, not process launches.
pub fn hook_entry_count(path: &Path) -> io::Result<usize> {
    count_matching_lines(path, |line| line == "hook stage=entry")
}

/// Count validated broker request records. These are written only after the
/// broker authorization checks pass, so they are not executable invocations.
pub fn validated_request_count(path: &Path) -> io::Result<usize> {
    count_matching_lines(path, |line| {
        line.starts_with("request event=PermissionRequest ")
    })
}

pub fn exact_request_count(
    path: &Path,
    tool_name: &str,
    tool_input: &serde_json::Value,
) -> io::Result<usize> {
    count_matching_lines(path, |line| {
        line.starts_with("request event=PermissionRequest ")
            && line.contains(&format!("tool_hash={} ", short_hash(tool_name)))
            && line.contains(&format!("command_hash={}", command_hash(Some(tool_input))))
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
            && line.contains(&format!("command_hash={}", command_hash(Some(tool_input))))
    })
}

fn count_matching_lines(path: &Path, predicate: impl Fn(&str) -> bool) -> io::Result<usize> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents.lines().filter(|line| predicate(line)).count()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

fn short_hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn command_hash(tool_input: Option<&serde_json::Value>) -> String {
    tool_input
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get("command"))
        .and_then(serde_json::Value::as_str)
        .map(short_hash)
        .unwrap_or_else(|| "none".into())
}

#[cfg(any(test, windows))]
fn recognized_command_wrapper(command: &str) -> &'static str {
    [
        ("cmd /c ", "cmd"),
        ("cmd.exe /c ", "cmd"),
        ("cmd /d /s /c ", "cmd"),
        ("cmd.exe /d /s /c ", "cmd"),
        ("powershell -command ", "powershell"),
        ("powershell.exe -command ", "powershell"),
        ("pwsh -command ", "powershell"),
        ("pwsh.exe -command ", "powershell"),
        ("sh -c ", "posix_shell"),
        ("bash -c ", "posix_shell"),
    ]
    .into_iter()
    .find_map(|(prefix, category)| {
        command
            .get(..prefix.len())
            .filter(|head| head.eq_ignore_ascii_case(prefix))
            .map(|_| category)
    })
    .unwrap_or("none")
}

fn parse_exact_command_diagnostic(line: &str) -> Option<String> {
    let fields = line.strip_prefix("hook exact_command ")?.split_whitespace();
    let fields = fields.collect::<Vec<_>>();
    if fields.len() != 9 {
        return None;
    }
    let expected_len = parse_length(fields[0], "expected_len=")?;
    let actual_len = parse_length(fields[1], "actual_len=")?;
    if expected_len > crate::protocol::MAX_INPUT_BYTES
        || actual_len > crate::protocol::MAX_INPUT_BYTES
    {
        return None;
    }
    let actual_present = parse_flag(fields[2], "actual_present=")?;
    if parse_flag(fields[3], "equal=")? != 0 {
        return None;
    }
    let leading_ws = parse_flag(fields[4], "leading_ws=")?;
    let trailing_ws = parse_flag(fields[5], "trailing_ws=")?;
    let cr = parse_flag(fields[6], "cr=")?;
    let lf = parse_flag(fields[7], "lf=")?;
    let wrapper = fields[8].strip_prefix("wrapper=")?;
    if !matches!(wrapper, "none" | "cmd" | "powershell" | "posix_shell") {
        return None;
    }
    Some(format!(
        "expected_len={expected_len} actual_len={actual_len} actual_present={actual_present} equal=0 leading_ws={leading_ws} trailing_ws={trailing_ws} cr={cr} lf={lf} wrapper={wrapper}"
    ))
}

fn parse_length(field: &str, prefix: &str) -> Option<usize> {
    field.strip_prefix(prefix)?.parse().ok()
}

fn parse_flag(field: &str, prefix: &str) -> Option<usize> {
    let value = parse_length(field, prefix)?;
    (value <= 1).then_some(value)
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
                "command": crate::compatibility::verification_probe_command(),
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
                "command": crate::compatibility::verification_probe_command(),
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
        assert!(!contents.contains(crate::compatibility::verification_probe_command()));
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
        assert_eq!(hook_entry_count(&path).unwrap(), 0);
        assert_eq!(validated_request_count(&path).unwrap(), 0);
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(contents.contains("event=PermissionRequest"));
        assert!(!contents.contains("Bash"));
    }

    #[test]
    fn verification_records_hashes_without_recording_request_content() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        let input = serde_json::json!({
            "command": "curl -I https://example.com",
            "description": "network-access example.com",
        });
        let expected_command = serde_json::json!({"command": "curl -I https://example.com"});
        hook_request_at(&path, Some("Bash"), Some("PermissionRequest"), Some(&input))
            .expect("write request record");
        hook_allow_emitted_at(&path, "Bash", Some(&input)).expect("write emission record");
        assert_eq!(validated_request_count(&path).unwrap(), 1);
        assert_eq!(
            exact_request_count(&path, "Bash", &expected_command).unwrap(),
            1
        );
        assert_eq!(
            emitted_allow_count(&path, "Bash", &expected_command).unwrap(),
            1
        );
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(!contents.contains("curl -I"));
    }

    #[test]
    fn hook_stage_diagnostics_are_fixed_and_summary_is_redacted() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        hook_stage_at(&path, "entry").expect("write entry stage");
        hook_stage_at(&path, "broker_error").expect("write broker stage");
        hook_rejection_at(&path, RejectionCategory::Ancestry).expect("write rejection");
        assert_eq!(hook_entry_count(&path).unwrap(), 1);
        assert_eq!(validated_request_count(&path).unwrap(), 0);
        assert!(hook_stage_at(&path, "not-a-stage").is_err());
        let summary = hook_diagnostic_summary(&path).expect("summarize hook stages");
        assert!(summary.contains("entry=1"));
        assert!(summary.contains("broker_error=1"));
        assert!(summary.contains("first_broker_rejection=ancestry"));
        assert!(summary.contains("ancestry=1"));
        assert!(!summary.contains("not-a-stage"));
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(!contents.contains("secret"));
        assert!(!contents.contains("pipe"));
    }

    #[test]
    fn exact_command_diagnostics_are_bounded_and_redacted() {
        let directory = TempDir::new().expect("temporary audit directory");
        let path = directory.path().join("audit.log");
        initialize(&path).expect("initialize audit");
        let expected = "curl.exe -I https://example.com";
        let actual = "cmd.exe /c secret-command\r\n";
        hook_exact_command_mismatch_at(&path, expected, Some(actual))
            .expect("write exact-command diagnostic");
        let summary = hook_diagnostic_summary(&path).expect("summarize exact command");
        assert!(summary.contains("exact_command_diagnostics=1"));
        assert!(summary.contains("expected_len=31"));
        assert!(summary.contains("actual_present=1"));
        assert!(summary.contains("leading_ws=0"));
        assert!(summary.contains("trailing_ws=1"));
        assert!(summary.contains("cr=1"));
        assert!(summary.contains("lf=1"));
        assert!(summary.contains("wrapper=cmd"));
        let contents = std::fs::read_to_string(path).expect("read diagnostic");
        assert!(!contents.contains(expected));
        assert!(!contents.contains("secret-command"));
    }
}
