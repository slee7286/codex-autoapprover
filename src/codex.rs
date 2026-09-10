use std::{
    env, fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};

pub struct Installation {
    pub path: PathBuf,
    pub version: String,
    pub version_diagnostic: Option<String>,
    pub launcher_kind: LauncherKind,
}

pub const UNKNOWN_VERSION: &str = "unknown";
const CAPABILITY_TIMEOUT: Duration = Duration::from_secs(5);
const CAPABILITY_OUTPUT_LIMIT: usize = 64 * 1024;

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

    let (version, version_diagnostic) = match version(&candidate.path) {
        Ok(version) => (version, None),
        Err(error) => (UNKNOWN_VERSION.to_owned(), Some(format!("{error:#}"))),
    };

    Ok(Installation {
        path: candidate.path.clone(),
        version,
        version_diagnostic,
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
        version_diagnostic: None,
        launcher_kind: launcher_kind(path),
    };
    let mut command = build_codex_command(&installation);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output =
        bounded_output(command).with_context(|| format!("run {} --version", path.display()))?;
    if output_size(&output) > CAPABILITY_OUTPUT_LIMIT {
        bail!("{} --version output was too large", path.display())
    }
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
        let parts: Vec<&str> = candidate.split('.').collect();
        if parts.len() == 3
            && parts.iter().all(|part| {
                !part.is_empty()
                    && (part.len() == 1 || !part.starts_with('0'))
                    && part.chars().all(|c| c.is_ascii_digit())
            })
        {
            return Ok(candidate.to_string());
        }
    }
    bail!("no semantic version found")
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum HookCapability {
    ReviewedLiveEvidence,
    SupportedByConfigurationProbe,
    Unsupported(&'static str),
    Inconclusive(&'static str),
    NotChecked(&'static str),
}

impl HookCapability {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReviewedLiveEvidence => "supported by reviewed live evidence",
            Self::SupportedByConfigurationProbe => "supported by non-live configuration probe",
            Self::Unsupported(_) => "unsupported by capability probe",
            Self::Inconclusive(_) => "capability probe inconclusive",
            Self::NotChecked(_) => "not checked",
        }
    }

    pub const fn reason(&self) -> Option<&'static str> {
        match self {
            Self::Unsupported(reason) | Self::Inconclusive(reason) | Self::NotChecked(reason) => {
                Some(reason)
            }
            Self::ReviewedLiveEvidence | Self::SupportedByConfigurationProbe => None,
        }
    }
}

pub fn detect_hook_capability(installation: &Installation, launcher: &Path) -> HookCapability {
    let config_override = hook_command_value(launcher);
    let mut config_command = build_codex_command(installation);
    config_command
        .arg("--help")
        .arg("-c")
        .arg(&config_override)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let config_output = match bounded_output(config_command) {
        Ok(output) => output,
        Err(_) => return HookCapability::Inconclusive("the configuration probe could not run"),
    };
    if !config_output.status.success() {
        return HookCapability::Unsupported(
            "the installed Codex rejected the child-local hook configuration",
        );
    }
    if output_size(&config_output) > CAPABILITY_OUTPUT_LIMIT
        || !output_contains(&config_output, "-c, --config")
    {
        return HookCapability::Inconclusive(
            "the configuration probe did not expose the required --config interface",
        );
    }

    let mut feature_command = build_codex_command(installation);
    feature_command
        .args(["features", "list", "-c"])
        .arg(&config_override)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let feature_output = match bounded_output(feature_command) {
        Ok(output) => output,
        Err(_) => return HookCapability::Inconclusive("the hooks feature probe could not run"),
    };
    if !feature_output.status.success() {
        return HookCapability::Inconclusive(
            "the installed Codex does not expose a usable feature-list probe",
        );
    }
    if output_size(&feature_output) > CAPABILITY_OUTPUT_LIMIT {
        return HookCapability::Inconclusive("the hooks feature probe output was too large");
    }
    if !hooks_feature_is_stable_and_enabled(&feature_output) {
        return HookCapability::Unsupported(
            "the installed Codex did not report stable, enabled hooks",
        );
    }
    HookCapability::SupportedByConfigurationProbe
}

fn bounded_output(mut command: Command) -> Result<Output> {
    let mut child = command.spawn().context("spawn Codex capability probe")?;
    let stdout = child
        .stdout
        .take()
        .context("capture Codex capability probe stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("capture Codex capability probe stderr")?;
    let stdout_thread = thread::spawn(move || read_probe_output(stdout));
    let stderr_thread = thread::spawn(move || read_probe_output(stderr));
    let deadline = Instant::now() + CAPABILITY_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child
                    .wait()
                    .context("reap timed-out Codex capability probe");
            }
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(anyhow::Error::new(error).context("poll Codex capability probe"));
            }
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| anyhow::anyhow!("Codex capability probe stdout reader failed"))??;
    let stderr = stderr_thread
        .join()
        .map_err(|_| anyhow::anyhow!("Codex capability probe stderr reader failed"))??;
    if timed_out {
        bail!("Codex capability probe timed out")
    }
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

fn read_probe_output(stream: impl Read) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    stream
        .take((CAPABILITY_OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut output)
        .context("read Codex capability probe output")?;
    Ok(output)
}

fn output_size(output: &Output) -> usize {
    output.stdout.len() + output.stderr.len()
}

fn output_contains(output: &Output, needle: &str) -> bool {
    String::from_utf8_lossy(&output.stdout).contains(needle)
        || String::from_utf8_lossy(&output.stderr).contains(needle)
}

fn hooks_feature_is_stable_and_enabled(output: &Output) -> bool {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout.lines().chain(stderr.lines()).any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() >= 3 && fields[0] == "hooks" && fields[1] == "stable" && fields[2] == "true"
    })
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
    #[cfg(windows)]
    {
        // Codex 0.153.2 forwards commandWindows to cmd.exe with a normal
        // Command::arg, so embedded quotes arrive as literal \" characters.
        windows_command_path(&absolute)
    }
    #[cfg(not(windows))]
    {
        shell_quote(&absolute)
    }
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

#[cfg(not(windows))]
fn shell_quote(path: &Path) -> String {
    let value = path.to_string_lossy();
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(windows)]
fn windows_command_path(path: &Path) -> String {
    let path = if windows_shell_safe(path) {
        path.to_path_buf()
    } else {
        short_windows_path(path).unwrap_or_else(|| path.to_path_buf())
    };
    let value = path.to_string_lossy();
    if windows_shell_safe(&path) {
        value.into_owned()
    } else {
        format!("\"{}\"", value.replace('"', "\\\""))
    }
}

#[cfg(windows)]
fn windows_shell_safe(path: &Path) -> bool {
    !path.to_string_lossy().chars().any(|character| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '&' | '|' | '<' | '>' | '^' | '(' | ')' | '%' | '!'
            )
    })
}

#[cfg(windows)]
fn short_windows_path(path: &Path) -> Option<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

    let input: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buffer = vec![0_u16; 260];
    loop {
        let length =
            unsafe { GetShortPathNameW(input.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) }
                as usize;
        if length == 0 {
            return None;
        }
        if length < buffer.len() {
            return Some(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        buffer.resize(length.saturating_add(1), 0);
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
        assert!(parse_version("codex-cli 0.153.4-rc.1").is_err());
        assert!(parse_version("codex-cli 0.153").is_err());
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

    #[test]
    fn windows_candidate_version_is_exact() {
        assert_eq!(parse_version("codex-cli 0.152.1").unwrap(), "0.152.1");
        assert!(parse_version("codex-cli 0.152.0").is_ok());
        assert_ne!(parse_version("codex-cli 0.152.0").unwrap(), "0.152.1");
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
    fn windows_hook_command_leaves_safe_paths_unquoted_for_legacy_cmd_invocation() {
        let snippet =
            hook_config_snippet(std::path::Path::new("C:\\tools\\codex-autoapprover.exe"));
        assert!(
            snippet.contains("commandWindows = \"C:\\\\tools\\\\codex-autoapprover.exe hook\"")
        );
        assert!(!snippet.contains("\\\"C:\\\\tools"));
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
}
