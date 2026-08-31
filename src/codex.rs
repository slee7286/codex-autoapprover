use std::{
    env, fs,
    path::PathBuf,
    process::{Command, ExitStatus, Stdio},
};

use anyhow::{Context, Result, bail};

pub struct Installation {
    pub path: PathBuf,
    pub version: String,
}

pub fn resolve() -> Result<PathBuf> {
    let candidate = which::which("codex").context("resolve the official `codex` executable")?;
    let resolved = fs::canonicalize(&candidate)
        .with_context(|| format!("canonicalize resolved codex path {}", candidate.display()))?;
    let launcher = fs::canonicalize(env::current_exe().context("resolve launcher path")?)
        .context("canonicalize launcher path")?;

    if resolved == launcher {
        bail!("resolved `codex` points to codex-autoapprover; refusing recursive launch")
    }
    if !resolved.is_file() {
        bail!(
            "resolved codex path is not a regular file: {}",
            resolved.display()
        )
    }

    Ok(candidate)
}

pub fn inspect() -> Result<Installation> {
    let path = resolve()?;
    let version = version(&path)?;
    Ok(Installation { path, version })
}

pub fn version(path: &PathBuf) -> Result<String> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {} --version", path.display()))?;
    if !output.status.success() {
        bail!(
            "{} --version exited with {}",
            path.display(),
            format_status(output.status)
        )
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_version(&stdout).context("parse Codex version output")
}

pub fn parse_version(output: &str) -> Result<String> {
    for token in output.split_whitespace() {
        let candidate = token.strip_prefix("codex-cli").unwrap_or(token);
        let candidate = candidate.strip_prefix('v').unwrap_or(candidate);
        if candidate.chars().next().is_some_and(|c| c.is_ascii_digit())
            && candidate.split('.').count() >= 3
            && candidate
                .split('.')
                .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
        {
            return Ok(candidate.to_string());
        }
    }
    bail!("no semantic version found")
}

pub fn status_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    status.code().unwrap_or(1)
}

pub fn hook_command_value(executable: &std::path::Path) -> String {
    let command = format!("{} hook", shell_quote(executable));
    format!(
        "hooks.PermissionRequest=[{{hooks=[{{type=\"command\",command={}}}]}}]",
        toml_quote(&command)
    )
}

pub fn hook_config_snippet(executable: &std::path::Path) -> String {
    format!(
        "[[hooks.PermissionRequest]]\n\n[[hooks.PermissionRequest.hooks]]\ntype = \"command\"\ncommand = {}\n",
        toml_quote(&format!("{} hook", shell_quote(executable)))
    )
}

fn shell_quote(path: &std::path::Path) -> String {
    let value = path.to_string_lossy();
    if cfg!(windows) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn toml_quote(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

fn format_status(status: ExitStatus) -> String {
    status
        .code()
        .map(|code| code.to_string())
        .unwrap_or_else(|| "signal".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_local_version_shape() {
        assert_eq!(parse_version("codex-cli 0.151.0").unwrap(), "0.151.0");
        assert_eq!(parse_version("codex-cli v1.2.3\n").unwrap(), "1.2.3");
        assert!(parse_version("not a version").is_err());
    }

    #[test]
    fn hook_config_uses_a_command_hook_and_not_a_approval_key() {
        let snippet = hook_config_snippet(std::path::Path::new("/tmp/codex-autoapprover"));
        assert!(snippet.contains("hooks.PermissionRequest"));
        assert!(snippet.contains("type = \"command\""));
        assert!(!snippet.contains("option 1"));
    }
}
