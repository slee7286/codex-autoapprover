use std::{env, path::Path, process::Command};

use anyhow::{Context, Result};

pub const SESSION_TOKEN_ENV: &str = "CODEX_AUTOAPPROVER_SESSION_TOKEN";
pub const EXPECTED_CWD_ENV: &str = "CODEX_AUTOAPPROVER_EXPECTED_CWD";
pub const PROTOCOL_ENV: &str = "CODEX_AUTOAPPROVER_HOOK_PROTOCOL";
pub const CODEX_VERSION_ENV: &str = "CODEX_AUTOAPPROVER_CODEX_VERSION";
pub const SURFACE_ENV: &str = "CODEX_AUTOAPPROVER_SURFACE";
pub const AUDIT_PATH_ENV: &str = "CODEX_AUTOAPPROVER_AUDIT_PATH";
pub const VERIFICATION_COMMAND_ENV: &str = "CODEX_AUTOAPPROVER_VERIFICATION_COMMAND";
pub const PROTOCOL_VERSION: &str = "permission-request-v1";

const TOKEN_BYTES: usize = 32;

pub fn arm_child(command: &mut Command, cwd: &Path, codex_version: &str) -> Result<()> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).context("generate per-session arming token")?;

    command.env(SESSION_TOKEN_ENV, hex(&bytes));
    command.env(EXPECTED_CWD_ENV, cwd);
    command.env(PROTOCOL_ENV, PROTOCOL_VERSION);
    command.env(CODEX_VERSION_ENV, codex_version);
    command.env(
        SURFACE_ENV,
        crate::compatibility::Surface::LocalCliLauncher.as_str(),
    );
    Ok(())
}

pub fn arm_child_with_audit(
    command: &mut Command,
    cwd: &Path,
    codex_version: &str,
    audit_path: &Path,
) -> Result<()> {
    arm_child(command, cwd, codex_version)?;
    command.env(AUDIT_PATH_ENV, audit_path);
    Ok(())
}

pub fn arm_child_for_verification(
    command: &mut Command,
    cwd: &Path,
    codex_version: &str,
    audit_path: &Path,
    exact_command: &str,
) -> Result<()> {
    arm_child_with_audit(command, cwd, codex_version, audit_path)?;
    command.env(VERIFICATION_COMMAND_ENV, exact_command);
    Ok(())
}

pub fn is_armed() -> bool {
    valid_token(env::var(SESSION_TOKEN_ENV).ok().as_deref())
        && env::var(PROTOCOL_ENV).ok().as_deref() == Some(PROTOCOL_VERSION)
        && env::var(EXPECTED_CWD_ENV)
            .map(|cwd| !cwd.is_empty())
            .unwrap_or(false)
        && env::var(CODEX_VERSION_ENV)
            .ok()
            .is_some_and(|version| crate::compatibility::verified_hook_support(&version))
        && env::var(SURFACE_ENV).ok().as_deref()
            == Some(crate::compatibility::Surface::LocalCliLauncher.as_str())
}

pub fn valid_token(token: Option<&str>) -> bool {
    token.is_some_and(|value| {
        value.len() == TOKEN_BYTES * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use std::process::Stdio;

    use super::*;

    #[test]
    fn tokens_must_be_full_lowercase_hex() {
        assert!(valid_token(Some(&"a".repeat(64))));
        assert!(!valid_token(Some("")));
        assert!(!valid_token(Some(&"A".repeat(64))));
        assert!(!valid_token(Some(&"0".repeat(63))));
        assert!(!valid_token(None));
    }

    #[cfg(unix)]
    #[test]
    fn arming_is_child_only_and_token_is_not_printed() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test ${#CODEX_AUTOAPPROVER_SESSION_TOKEN} -eq 64 && test -n \"$CODEX_AUTOAPPROVER_EXPECTED_CWD\"")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        arm_child(
            &mut command,
            Path::new("/tmp/codex-hook-fixture"),
            "0.151.0",
        )
        .expect("arm child");
        assert!(std::env::var(SESSION_TOKEN_ENV).is_err());
        assert!(std::env::var(CODEX_VERSION_ENV).is_err());
        assert!(command.status().expect("run child").success());
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_children_receive_distinct_tokens() {
        let directory = tempfile::TempDir::new().expect("temporary directory");
        let first_path = directory.path().join("first-token");
        let second_path = directory.path().join("second-token");
        let mut first = Command::new("sh");
        first
            .args([
                "-c",
                "printf %s \"$CODEX_AUTOAPPROVER_SESSION_TOKEN\" > \"$TOKEN_FILE\"",
            ])
            .env("TOKEN_FILE", &first_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut second = Command::new("sh");
        second
            .args([
                "-c",
                "printf %s \"$CODEX_AUTOAPPROVER_SESSION_TOKEN\" > \"$TOKEN_FILE\"",
            ])
            .env("TOKEN_FILE", &second_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        arm_child(&mut first, directory.path(), "0.151.0").expect("arm first child");
        arm_child(&mut second, directory.path(), "0.151.0").expect("arm second child");
        assert!(first.status().expect("run first child").success());
        assert!(second.status().expect("run second child").success());
        assert_ne!(
            std::fs::read_to_string(first_path).expect("first token"),
            std::fs::read_to_string(second_path).expect("second token")
        );
    }
}
