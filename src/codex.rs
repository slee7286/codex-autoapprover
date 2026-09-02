use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use anyhow::{Context, Result, bail};

pub struct Installation {
    pub path: PathBuf,
    pub version: String,
    pub launcher_kind: LauncherKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum LauncherKind {
    Executable,
    Cmd,
    Ps1,
    Other,
}

#[allow(dead_code)]
pub fn resolve() -> Result<PathBuf> {
    let installation = inspect()?;
    Ok(installation.path)
}

pub fn inspect() -> Result<Installation> {
    let candidate = resolve_codex_candidate()?;
    let resolved =
        normalize_windows_path(fs::canonicalize(&candidate.path).with_context(|| {
            format!(
                "canonicalize resolved codex path {}",
                candidate.path.display()
            )
        })?);
    let launcher = normalize_windows_path(
        fs::canonicalize(env::current_exe().context("resolve launcher path")?)
            .context("canonicalize launcher path")?,
    );

    if resolved == launcher {
        bail!("resolved `codex` points to codex-autoapprover; refusing recursive launch")
    }
    if !resolved.is_file() {
        bail!(
            "resolved codex path is not a regular file: {}",
            resolved.display()
        )
    }

    Ok(Installation {
        path: candidate.path.clone(),
        version: version(&candidate.path)?,
        launcher_kind: candidate.kind,
    })
}

struct Candidate {
    path: PathBuf,
    kind: LauncherKind,
}

fn resolve_codex_candidate() -> Result<Candidate> {
    #[cfg(windows)]
    {
        resolve_windows_codex()
    }
    #[cfg(not(windows))]
    {
        let path = which::which("codex").context("resolve the official `codex` executable")?;
        Ok(Candidate {
            path,
            kind: LauncherKind::Executable,
        })
    }
}

#[cfg(windows)]
fn resolve_windows_codex() -> Result<Candidate> {
    let mut candidates = Vec::new();
    if let Some(path_value) = env::var_os("PATH") {
        for directory in env::split_paths(&path_value) {
            for suffix in [".exe", ".cmd", ".ps1", ""] {
                let mut name = std::ffi::OsString::from("codex");
                name.push(suffix);
                let path = directory.join(name);
                if path.is_file() {
                    candidates.push(path);
                }
            }
        }
    }
    if candidates.is_empty() {
        bail!("resolve the official `codex` executable")
    }
    let launcher = normalize_windows_path(
        fs::canonicalize(env::current_exe().context("resolve launcher path")?)
            .context("canonicalize launcher path")?,
    );
    for path in candidates {
        let kind = launcher_kind(&path);
        let resolved = normalize_windows_path(fs::canonicalize(&path).unwrap_or(path));
        if resolved == launcher {
            continue;
        }
        return Ok(Candidate {
            path: resolved,
            kind,
        });
    }
    bail!("resolved `codex` points to codex-autoapprover; refusing recursive launch")
}

#[allow(dead_code)]
fn launcher_kind(path: &Path) -> LauncherKind {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("exe") => LauncherKind::Executable,
        Some("cmd") => LauncherKind::Cmd,
        Some("ps1") => LauncherKind::Ps1,
        _ => LauncherKind::Other,
    }
}

pub fn version(path: &Path) -> Result<String> {
    let installation = Installation {
        path: path.to_path_buf(),
        version: String::new(),
        launcher_kind: launcher_kind(path),
    };
    let output = build_codex_command(&installation)
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

pub fn hook_command_value(executable: &Path) -> String {
    let hook = format!("{} hook", absolute_shell_quote(executable));
    if cfg!(windows) {
        format!(
            "hooks.PermissionRequest=[{{hooks=[{{type=\"command\",command=\"\",commandWindows={}}}]}}]",
            toml_quote(&hook)
        )
    } else {
        format!(
            "hooks.PermissionRequest=[{{hooks=[{{type=\"command\",command={}}}]}}]",
            toml_quote(&hook)
        )
    }
}

pub fn hook_config_snippet(executable: &Path) -> String {
    let hook = format!("{} hook", absolute_shell_quote(executable));
    if cfg!(windows) {
        format!(
            "[[hooks.PermissionRequest]]\n\n[[hooks.PermissionRequest.hooks]]\ntype = \"command\"\ncommandWindows = {}\n",
            toml_quote(&hook)
        )
    } else {
        format!(
            "[[hooks.PermissionRequest]]\n\n[[hooks.PermissionRequest.hooks]]\ntype = \"command\"\ncommand = {}\n",
            toml_quote(&hook)
        )
    }
}

pub fn build_codex_command(installation: &Installation) -> Command {
    match installation.launcher_kind {
        LauncherKind::Ps1 => {
            let mut command = Command::new("powershell");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ]);
            command.arg(&installation.path);
            command
        }
        _ => Command::new(&installation.path),
    }
}

fn absolute_shell_quote(path: &Path) -> String {
    let absolute =
        normalize_windows_path(fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    shell_quote(&absolute)
}

#[cfg(windows)]
fn normalize_windows_path(path: PathBuf) -> PathBuf {
    let value = path.to_string_lossy();
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path
    }
}

#[cfg(not(windows))]
fn normalize_windows_path(path: PathBuf) -> PathBuf {
    path
}

fn shell_quote(path: &Path) -> String {
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

    #[cfg(windows)]
    #[test]
    fn windows_hook_config_uses_command_windows_field() {
        let snippet =
            hook_config_snippet(std::path::Path::new("C:\\tools\\codex-autoapprover.exe"));
        assert!(snippet.contains("commandWindows"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_hook_command_quotes_paths_with_shell_metacharacters() {
        let snippet = hook_config_snippet(std::path::Path::new(
            "C:\\space & unicode-测试\\codex-autoapprover.exe",
        ));
        assert!(
            snippet.contains("\\\"C:\\\\space & unicode-测试\\\\codex-autoapprover.exe\\\" hook")
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_launcher_kind_recognizes_supported_shims() {
        assert_eq!(
            launcher_kind(std::path::Path::new("codex.exe")),
            LauncherKind::Executable
        );
        assert_eq!(
            launcher_kind(std::path::Path::new("codex.cmd")),
            LauncherKind::Cmd
        );
        assert_eq!(
            launcher_kind(std::path::Path::new("codex.ps1")),
            LauncherKind::Ps1
        );
        assert_eq!(
            launcher_kind(std::path::Path::new("codex")),
            LauncherKind::Other
        );
    }

    #[test]
    fn windows_candidate_version_is_exact() {
        assert_eq!(parse_version("codex-cli 0.152.1").unwrap(), "0.152.1");
        assert!(parse_version("codex-cli 0.152.0").is_ok());
        assert_ne!(parse_version("codex-cli 0.152.0").unwrap(), "0.152.1");
    }
}
