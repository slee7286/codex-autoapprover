use std::{env, path::Path, process::Command};

use anyhow::{Context, Result};

pub const SESSION_TOKEN_ENV: &str = "CODEX_AUTOAPPROVER_SESSION_TOKEN";
pub const SESSION_SOCKET_ENV: &str = "CODEX_AUTOAPPROVER_SESSION_SOCKET";
pub const PROTOCOL_ENV: &str = "CODEX_AUTOAPPROVER_HOOK_PROTOCOL";
#[allow(dead_code)]
pub const AUDIT_PATH_ENV: &str = "CODEX_AUTOAPPROVER_AUDIT_PATH";
pub const PROTOCOL_VERSION: &str = "permission-request-v1";

const TOKEN_BYTES: usize = 32;

pub fn new_secret() -> Result<String> {
    let mut bytes = [0_u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).context("generate per-session arming token")?;
    Ok(hex(&bytes))
}

pub fn arm_child(command: &mut Command, socket: &Path, secret: &str) -> Result<()> {
    if !valid_token(Some(secret)) {
        anyhow::bail!("generated session secret has an invalid shape")
    }
    command.env(SESSION_TOKEN_ENV, secret);
    command.env(SESSION_SOCKET_ENV, socket);
    command.env(PROTOCOL_ENV, PROTOCOL_VERSION);
    Ok(())
}

pub fn is_armed() -> bool {
    valid_token(env::var(SESSION_TOKEN_ENV).ok().as_deref())
        && env::var(PROTOCOL_ENV).ok().as_deref() == Some(PROTOCOL_VERSION)
        && env::var(SESSION_SOCKET_ENV)
            .map(|cwd| !cwd.is_empty())
            .unwrap_or(false)
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
    use super::*;

    #[cfg(unix)]
    use std::process::Stdio;

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
        let secret = new_secret().expect("secret");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("test ${#CODEX_AUTOAPPROVER_SESSION_TOKEN} -eq 64 && test -n \"$CODEX_AUTOAPPROVER_SESSION_SOCKET\"")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        arm_child(&mut command, Path::new("/tmp/codex-hook-fixture"), &secret).expect("arm child");
        assert!(std::env::var(SESSION_TOKEN_ENV).is_err());
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
        arm_child(
            &mut first,
            directory.path(),
            &new_secret().expect("first secret"),
        )
        .expect("arm first child");
        arm_child(
            &mut second,
            directory.path(),
            &new_secret().expect("second secret"),
        )
        .expect("arm second child");
        assert!(first.status().expect("run first child").success());
        assert!(second.status().expect("run second child").success());
        assert_ne!(
            std::fs::read_to_string(first_path).expect("first token"),
            std::fs::read_to_string(second_path).expect("second token")
        );
    }
}
