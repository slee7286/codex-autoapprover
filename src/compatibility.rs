//! Typed, exact compatibility metadata for combinations this launcher may arm.

pub const LOCAL_VERIFICATION_TARGET: &str = "0.151.0";
pub const WINDOWS_VERIFICATION_TARGET: &str = "0.152.1";
pub const SUPPORTED_HOOK_PROTOCOL: &str = "permission-request-v1";
pub const AUTOAPPROVER_RELEASE: &str = "0.1.0";

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
        #[cfg(target_os = "linux")]
        {
            Self::Linux
        }
        #[cfg(target_os = "macos")]
        {
            Self::MacOs
        }
        #[cfg(windows)]
        {
            Self::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self::Other
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
            Self::Windows => "Windows",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Surface {
    LocalCliLauncher,
    VsCodeIde,
    DesktopApp,
    RemoteEnvironment,
    Container,
    Wsl,
    SshHostedIde,
    CodexCloud,
    Unknown,
}

impl Surface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalCliLauncher => "local CLI launcher",
            Self::VsCodeIde => "VS Code/IDE",
            Self::DesktopApp => "desktop app",
            Self::RemoteEnvironment => "remote environment",
            Self::Container => "container",
            Self::Wsl => "WSL",
            Self::SshHostedIde => "SSH-hosted IDE session",
            Self::CodexCloud => "Codex cloud",
            Self::Unknown => "unknown surface",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservedToolType {
    Bash,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseBehavior {
    OneRequestAllow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum VerificationStatus {
    Verified,
    Candidate,
    Experimental,
    Unverified,
}

impl VerificationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Candidate => "candidate/unverified",
            Self::Experimental => "experimental",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum VerificationMethod {
    IsolatedLiveEndToEndTest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityEntry {
    pub codex_version: &'static str,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_event: &'static str,
    pub hook_protocol: &'static str,
    pub observed_tool_type: ObservedToolType,
    pub response_behavior: ResponseBehavior,
    pub verification_status: VerificationStatus,
    pub verification_method: VerificationMethod,
    pub autoapprover_release: &'static str,
    pub evidence_summary: &'static str,
}

pub const COMPATIBILITY_REGISTRY: &[CompatibilityEntry] = &[
    CompatibilityEntry {
        codex_version: LOCAL_VERIFICATION_TARGET,
        operating_system: OperatingSystem::Linux,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Verified,
        verification_method: VerificationMethod::IsolatedLiveEndToEndTest,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "Second isolated live verification: one PermissionRequest, one structured allow, exact harmless curl completed with HTTP/2 200, no approval prompt, clean temporary repository, and complete temporary-state cleanup.",
    },
    CompatibilityEntry {
        codex_version: WINDOWS_VERIFICATION_TARGET,
        operating_system: OperatingSystem::Windows,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Candidate,
        verification_method: VerificationMethod::IsolatedLiveEndToEndTest,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "Candidate only: native Windows Codex CLI 0.152.1 local launcher path pending isolated live verification and manual evidence review.",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityRequest<'a> {
    pub codex_version: &'a str,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_protocol: &'a str,
}

fn matching_entry(request: CompatibilityRequest<'_>) -> Option<&'static CompatibilityEntry> {
    COMPATIBILITY_REGISTRY.iter().find(|entry| {
        entry.autoapprover_release == AUTOAPPROVER_RELEASE
            && entry.codex_version == request.codex_version
            && entry.operating_system == request.operating_system
            && entry.surface == request.surface
            && entry.hook_event == crate::protocol::PERMISSION_REQUEST_EVENT
            && entry.hook_protocol == request.hook_protocol
    })
}

pub fn verified_entry(request: CompatibilityRequest<'_>) -> Option<&'static CompatibilityEntry> {
    matching_entry(request)
        .filter(|entry| entry.verification_status == VerificationStatus::Verified)
}

pub fn candidate_entry(request: CompatibilityRequest<'_>) -> Option<&'static CompatibilityEntry> {
    matching_entry(request)
        .filter(|entry| entry.verification_status == VerificationStatus::Candidate)
}

pub fn verified_hook_support_for(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
) -> bool {
    verified_entry(CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface,
        hook_protocol,
    })
    .is_some()
}

pub fn verified_or_candidate_hook_support_for(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
) -> bool {
    let request = CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface,
        hook_protocol,
    };
    verified_entry(request).is_some() || candidate_entry(request).is_some()
}

pub fn observed_tool_supported(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
    tool_name: &str,
) -> bool {
    matching_entry(CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface,
        hook_protocol,
    })
    .is_some_and(|entry| {
        matches!(entry.observed_tool_type, ObservedToolType::Bash) && tool_name == "Bash"
    })
}

#[allow(dead_code)]
pub fn verified_hook_support(version: &str) -> bool {
    verified_hook_support_for(
        version,
        OperatingSystem::current(),
        Surface::LocalCliLauncher,
        SUPPORTED_HOOK_PROTOCOL,
    )
}

pub fn status_for_version(version: &str) -> &'static str {
    let request = CompatibilityRequest {
        codex_version: version,
        operating_system: OperatingSystem::current(),
        surface: Surface::LocalCliLauncher,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
    };
    if let Some(entry) = verified_entry(request) {
        entry.verification_status.as_str()
    } else if candidate_entry(request).is_some() {
        VerificationStatus::Candidate.as_str()
    } else {
        "unverified"
    }
}

pub fn verification_target_for_current_platform() -> &'static str {
    if cfg!(windows) {
        WINDOWS_VERIFICATION_TARGET
    } else {
        LOCAL_VERIFICATION_TARGET
    }
}

pub fn verification_version_matches(actual: &str, expected: &str) -> bool {
    !actual.is_empty()
        && actual == expected
        && ((cfg!(target_os = "linux") && expected == LOCAL_VERIFICATION_TARGET)
            || (cfg!(windows) && expected == WINDOWS_VERIFICATION_TARGET))
}

pub fn is_native_windows_runtime() -> bool {
    cfg!(windows) && !is_wsl_runtime()
}

pub fn is_wsl_runtime() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/version")
            .map(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("microsoft") || lower.contains("wsl")
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_linux_verified_and_windows_candidate_entries() {
        assert_eq!(COMPATIBILITY_REGISTRY.len(), 2);
        assert_eq!(COMPATIBILITY_REGISTRY[0].codex_version, "0.151.0");
        assert_eq!(
            COMPATIBILITY_REGISTRY[0].verification_status,
            VerificationStatus::Verified
        );
        assert_eq!(COMPATIBILITY_REGISTRY[1].codex_version, "0.152.1");
        assert_eq!(
            COMPATIBILITY_REGISTRY[1].operating_system,
            OperatingSystem::Windows
        );
        assert_eq!(
            COMPATIBILITY_REGISTRY[1].verification_status,
            VerificationStatus::Candidate
        );
    }

    #[test]
    fn adjacent_malformed_and_unknown_versions_are_unverified() {
        for version in [
            "0.150.0",
            "0.150.9",
            "0.152.0",
            "",
            "codex-cli 0.151.0",
            "v0.151.0",
        ] {
            assert!(!verified_hook_support_for(
                version,
                OperatingSystem::Linux,
                Surface::LocalCliLauncher,
                SUPPORTED_HOOK_PROTOCOL
            ));
        }
        for version in ["0.151.0", "0.152.0", "0.153.0"] {
            assert!(!verified_hook_support_for(
                version,
                OperatingSystem::Windows,
                Surface::LocalCliLauncher,
                SUPPORTED_HOOK_PROTOCOL
            ));
        }
    }

    #[test]
    fn windows_candidate_is_not_production_verified() {
        assert!(!verified_hook_support_for(
            "0.152.1",
            OperatingSystem::Windows,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        assert!(verified_or_candidate_hook_support_for(
            "0.152.1",
            OperatingSystem::Windows,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
    }

    #[test]
    fn verification_binding_is_exact_without_promoting_support() {
        if cfg!(unix) {
            assert!(verification_version_matches("0.151.0", "0.151.0"));
            assert!(!verification_version_matches("0.151.1", "0.151.0"));
            assert!(verified_hook_support("0.151.0"));
        } else {
            assert!(verification_version_matches("0.152.1", "0.152.1"));
            assert!(!verification_version_matches("0.152.0", "0.152.1"));
            assert!(!verified_hook_support("0.152.1"));
        }
    }

    #[test]
    fn unsupported_platforms_and_surfaces_are_unverified() {
        assert!(!verified_hook_support_for(
            "0.151.0",
            OperatingSystem::MacOs,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        for surface in [
            Surface::VsCodeIde,
            Surface::DesktopApp,
            Surface::RemoteEnvironment,
            Surface::Container,
            Surface::Wsl,
            Surface::SshHostedIde,
            Surface::CodexCloud,
        ] {
            assert!(!verified_hook_support_for(
                "0.151.0",
                OperatingSystem::Linux,
                surface,
                SUPPORTED_HOOK_PROTOCOL
            ));
        }
    }

    #[test]
    fn unsupported_hook_protocol_is_unverified() {
        assert!(!verified_hook_support_for(
            "0.151.0",
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            "permission-request-v2"
        ));
    }

    #[test]
    fn only_the_reviewed_tool_type_is_supported() {
        assert!(observed_tool_supported(
            "0.151.0",
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL,
            "Bash"
        ));
        assert!(!observed_tool_supported(
            "0.151.0",
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL,
            "Mcp"
        ));
    }
}
