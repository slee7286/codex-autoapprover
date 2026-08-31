//! Typed, exact compatibility metadata for combinations this launcher may arm.
//!
//! A version is supported only for the operating system, launcher surface, hook
//! protocol, and observed tool type recorded by the reviewed evidence.

pub const LOCAL_VERIFICATION_TARGET: &str = "0.151.0";
pub const SUPPORTED_HOOK_PROTOCOL: &str = "permission-request-v1";
pub const AUTOAPPROVER_RELEASE: &str = "0.1.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Future entries intentionally model unsupported targets explicitly.
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
        #[cfg(target_os = "windows")]
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
#[allow(dead_code)] // Future entries intentionally model unsupported surfaces explicitly.
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
#[allow(dead_code)] // Future registry entries may be experimental or unverified.
pub enum VerificationStatus {
    Verified,
    Experimental,
    Unverified,
}

impl VerificationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Experimental => "experimental",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Retained as typed metadata for future registry entries.
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

/// The reviewed production compatibility registry.
pub const COMPATIBILITY_REGISTRY: &[CompatibilityEntry] = &[CompatibilityEntry {
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
}];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityRequest<'a> {
    pub codex_version: &'a str,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_protocol: &'a str,
}

pub fn verified_entry(request: CompatibilityRequest<'_>) -> Option<&'static CompatibilityEntry> {
    COMPATIBILITY_REGISTRY.iter().find(|entry| {
        entry.verification_status == VerificationStatus::Verified
            && entry.autoapprover_release == AUTOAPPROVER_RELEASE
            && entry.codex_version == request.codex_version
            && entry.operating_system == request.operating_system
            && entry.surface == request.surface
            && entry.hook_event == crate::protocol::PERMISSION_REQUEST_EVENT
            && entry.hook_protocol == request.hook_protocol
    })
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

pub fn observed_tool_supported(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
    tool_name: &str,
) -> bool {
    verified_entry(CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface,
        hook_protocol,
    })
    .is_some_and(|entry| {
        matches!(entry.observed_tool_type, ObservedToolType::Bash) && tool_name == "Bash"
    })
}

pub fn verified_hook_support(version: &str) -> bool {
    verified_hook_support_for(
        version,
        OperatingSystem::current(),
        Surface::LocalCliLauncher,
        SUPPORTED_HOOK_PROTOCOL,
    )
}

pub fn status_for_version(version: &str) -> &'static str {
    if verified_hook_support(version) {
        VerificationStatus::Verified.as_str()
    } else {
        "unverified"
    }
}

/// The verification path requires exact version equality and does not itself
/// promote a production registry entry.
pub fn verification_version_matches(actual: &str, expected: &str) -> bool {
    !actual.is_empty() && actual == expected && actual == LOCAL_VERIFICATION_TARGET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_exactly_the_reviewed_linux_cli_target() {
        assert_eq!(COMPATIBILITY_REGISTRY.len(), 1);
        let entry = &COMPATIBILITY_REGISTRY[0];
        assert_eq!(entry.codex_version, "0.151.0");
        assert_eq!(entry.operating_system, OperatingSystem::Linux);
        assert_eq!(entry.surface, Surface::LocalCliLauncher);
        assert_eq!(entry.hook_event, "PermissionRequest");
        assert_eq!(entry.hook_protocol, SUPPORTED_HOOK_PROTOCOL);
        assert_eq!(entry.observed_tool_type, ObservedToolType::Bash);
        assert_eq!(entry.verification_status, VerificationStatus::Verified);
        assert_eq!(entry.autoapprover_release, "0.1.0");
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
    }

    #[test]
    fn verification_binding_is_exact_without_promoting_support() {
        assert!(verification_version_matches("0.151.0", "0.151.0"));
        assert!(!verification_version_matches("0.151.1", "0.151.0"));
        assert!(!verification_version_matches("1.2.3", "1.2.3"));
        assert!(verified_hook_support("0.151.0"));
    }

    #[test]
    fn unsupported_platforms_and_surfaces_are_unverified() {
        for operating_system in [OperatingSystem::MacOs, OperatingSystem::Windows] {
            assert!(!verified_hook_support_for(
                "0.151.0",
                operating_system,
                Surface::LocalCliLauncher,
                SUPPORTED_HOOK_PROTOCOL
            ));
        }
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
