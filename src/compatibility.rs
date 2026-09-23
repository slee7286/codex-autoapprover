//! Isolated verifier metadata only. Production authority lives in certification.rs.
use crate::arming;

pub const SUPPORTED_HOOK_PROTOCOL: &str = arming::PROTOCOL_VERSION;

#[cfg(windows)]
const VERIFICATION_CURL: &str = "curl.exe";
#[cfg(not(windows))]
const VERIFICATION_CURL: &str = "curl";

pub(crate) fn verification_probe_command(port: u16, nonce: &str) -> Option<String> {
    if port == 0
        || nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some(format!(
        "{VERIFICATION_CURL} -fsSI --max-time 10 --noproxy 127.0.0.1 http://127.0.0.1:{port}/{nonce}"
    ))
}

pub(crate) fn is_verification_probe_command(command: &str) -> bool {
    let Some(endpoint) = command.strip_prefix(&format!(
        "{VERIFICATION_CURL} -fsSI --max-time 10 --noproxy 127.0.0.1 http://127.0.0.1:"
    )) else {
        return false;
    };
    let Some((port, nonce)) = endpoint.split_once('/') else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    verification_probe_command(port, nonce).as_deref() == Some(command)
}

#[cfg(test)]
pub(crate) fn verification_probe_command_fixture() -> &'static str {
    if cfg!(windows) {
        "curl.exe -fsSI --max-time 10 --noproxy 127.0.0.1 http://127.0.0.1:47123/0123456789abcdef0123456789abcdef"
    } else {
        "curl -fsSI --max-time 10 --noproxy 127.0.0.1 http://127.0.0.1:47123/0123456789abcdef0123456789abcdef"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum OperatingSystem {
    Linux,
    MacOs,
    Windows,
    Other,
}
impl OperatingSystem {
    pub const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::Windows => "Windows",
            Self::MacOs => "macOS",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    LocalCliLauncher,
}
impl Surface {
    pub const fn as_str(self) -> &'static str {
        "local CLI launcher"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationTarget {
    pub version: String,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_protocol: &'static str,
    pub observed_tool_type: &'static str,
}

pub fn verification_schema(version: &str, tool: &str) -> bool {
    if tool != "Bash" || crate::codex::parse_version(&format!("codex-cli {version}")).is_err() {
        return false;
    }
    let numbers = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(numbers) = numbers else {
        return false;
    };
    let baseline = if cfg!(windows) {
        [0, 152, 1]
    } else {
        [0, 151, 0]
    };
    numbers.as_slice() >= baseline.as_slice()
}

pub fn resolved_verification_target(version: &str) -> Option<VerificationTarget> {
    if !verification_schema(version, "Bash") {
        return None;
    }
    Some(VerificationTarget {
        version: version.into(),
        operating_system: OperatingSystem::current(),
        surface: Surface::LocalCliLauncher,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: "Bash",
    })
}

pub fn verification_version_matches(actual: &str, target: &VerificationTarget) -> bool {
    actual == target.version
}
pub fn is_wsl_runtime() -> bool {
    crate::environment::surface().is_ok_and(|s| s == "wsl")
}
pub fn is_native_windows_runtime() -> bool {
    cfg!(windows) && crate::environment::surface().is_ok_and(|s| s == "native-cli")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifier_is_exactly_scoped_and_never_a_production_certificate() {
        assert!(verification_schema("0.156.0", "Bash"));
        assert!(!verification_schema("0.156.0", "apply_patch"));
        assert!(!verification_schema("0.156.0-rc.1", "Bash"));
        let target = resolved_verification_target("0.156.0").unwrap();
        assert!(!verification_version_matches("0.157.0", &target));
        assert!(is_verification_probe_command(
            verification_probe_command_fixture()
        ));
        assert!(!is_verification_probe_command(
            "curl -I https://example.com"
        ));
        assert!(!is_verification_probe_command(&format!(
            "{} && echo extra",
            verification_probe_command_fixture()
        )));
        assert!(!is_verification_probe_command(
            &verification_probe_command(47123, "0123456789abcdef0123456789abcdef")
                .unwrap()
                .replace("127.0.0.1", "example.com")
        ));
        assert!(
            !crate::certification::Manifest::embedded()
                .unwrap()
                .admits(&crate::certification::fixture_target())
        );
    }
}
