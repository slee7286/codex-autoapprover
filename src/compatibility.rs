//! Isolated verifier metadata only. Production authority lives in certification.rs.
use crate::arming;

pub const SUPPORTED_HOOK_PROTOCOL: &str = arming::PROTOCOL_VERSION;

#[cfg(windows)]
pub(crate) const fn verification_probe_command() -> &'static str {
    "curl.exe -I https://example.com"
}
#[cfg(not(windows))]
pub(crate) const fn verification_probe_command() -> &'static str {
    "curl -I https://example.com"
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
    pub command: &'static str,
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
        command: verification_probe_command(),
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
        assert!(
            !crate::certification::Manifest::embedded()
                .unwrap()
                .admits(&crate::certification::fixture_target())
        );
    }
}
