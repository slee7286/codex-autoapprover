use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use sha2::{Digest, Sha256};

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

pub fn initialize(path: &Path) -> io::Result<()> {
    append_private(path, b"")
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

pub fn invocation_count(path: &Path) -> io::Result<usize> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents
            .lines()
            .filter(|line| line.starts_with("invoked event="))
            .count()),
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
        assert_eq!(invocation_count(&path).unwrap(), 1);
        let contents = std::fs::read_to_string(path).expect("read audit");
        assert!(contents.contains("event=PermissionRequest"));
        assert!(!contents.contains("Bash"));
    }
}
