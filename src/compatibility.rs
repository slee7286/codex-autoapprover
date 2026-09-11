//! Compatibility policy and metadata for the local CLI hook adapter.
//!
//! Version eligibility, hook capability, runtime schema validation, review
//! status, and active session arming are intentionally separate concepts.

use serde::{Deserialize, Serialize};

pub const LOCAL_VERIFICATION_TARGET: &str = "0.153.0";
pub const PREVIOUS_LOCAL_VERIFIED_VERSION: &str = "0.151.0";
pub const WINDOWS_VERIFICATION_TARGET: &str = "0.152.1";
pub const WINDOWS_VERIFIED_VERSION: &str = "0.153.2";
pub const WINDOWS_NEWLY_VERIFIED_VERSION: &str = "0.154.0";
pub const LINUX_ADAPTER_BASELINE: &str = "0.153.0";
pub const WINDOWS_ADAPTER_BASELINE: &str = "0.152.1";
pub const LINUX_REQUESTED_EXPERIMENTAL_TARGET: &str = "0.153.4";
pub const SUPPORTED_HOOK_PROTOCOL: &str = "permission-request-v1";
pub const AUTOAPPROVER_RELEASE: &str = "0.1.0";

#[cfg(windows)]
pub(crate) const fn verification_probe_command() -> &'static str {
    "curl.exe -I https://example.com"
}

#[cfg(not(windows))]
pub(crate) const fn verification_probe_command() -> &'static str {
    "curl -I https://example.com"
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
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
            Self::Experimental => "experimental/unverified",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationMethod {
    IsolatedLiveEndToEndTest,
    CapabilityProbeOnly,
    RequestedExperimentalTarget,
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
        codex_version: PREVIOUS_LOCAL_VERIFIED_VERSION,
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
        codex_version: LOCAL_VERIFICATION_TARGET,
        operating_system: OperatingSystem::Linux,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Experimental,
        verification_method: VerificationMethod::CapabilityProbeOnly,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "Installed Linux target was inspected, but no independently identifiable reviewed live evidence is retained in this checkout; non-live capability probes only, so the tuple remains experimental/unverified.",
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
    CompatibilityEntry {
        codex_version: WINDOWS_VERIFIED_VERSION,
        operating_system: OperatingSystem::Windows,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Verified,
        verification_method: VerificationMethod::IsolatedLiveEndToEndTest,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "User-supplied native Windows live verification: Codex CLI 0.153.2, one executable hook entry, one validated PermissionRequest, one exact curl.exe command match, one broker allow with acknowledged response, one structured allow emission, HTTP 200, no observed manual approval prompt, clean temporary repository before and after, complete cleanup, and verifier exit 0. Evidence and tested uncommitted implementation hashes are recorded in docs/compatibility.md.",
    },
    CompatibilityEntry {
        codex_version: LINUX_REQUESTED_EXPERIMENTAL_TARGET,
        operating_system: OperatingSystem::Linux,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Experimental,
        verification_method: VerificationMethod::RequestedExperimentalTarget,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "User-requested experimental target; stable-version eligibility and non-live hook/configuration capability checks only; no live protocol verification.",
    },
    CompatibilityEntry {
        codex_version: WINDOWS_NEWLY_VERIFIED_VERSION,
        operating_system: OperatingSystem::Windows,
        surface: Surface::LocalCliLauncher,
        hook_event: crate::protocol::PERMISSION_REQUEST_EVENT,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: ObservedToolType::Bash,
        response_behavior: ResponseBehavior::OneRequestAllow,
        verification_status: VerificationStatus::Verified,
        verification_method: VerificationMethod::IsolatedLiveEndToEndTest,
        autoapprover_release: AUTOAPPROVER_RELEASE,
        evidence_summary: "User-supplied native Windows live verification: Codex CLI 0.154.0, one executable entry, one validated PermissionRequest, one exact curl.exe probe match, one allow record, one structured allow emission, one acknowledged broker response, stdout written once, HTTP 200, no manual approval prompt in the supplied transcript, child and verifier exit 0, clean temporary repository, successful cleanup, and zero broker errors, no-decision results, or rejection counters. Pre-launch baseline output was not supplied; one startup issue was mentioned without contents, so neither is interpreted as additional evidence.",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompatibilityRequest<'a> {
    pub codex_version: &'a str,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub hook_protocol: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KnownIncompatibleExclusion {
    pub codex_version: &'static str,
    pub operating_system: OperatingSystem,
    pub surface: Surface,
    pub reason: &'static str,
}

/// Explicit release exclusions live here instead of being hidden in version
/// comparisons. This release precedes the inspected Windows adapter baseline;
/// retaining it explicitly prevents a later baseline refactor from arming it.
pub const KNOWN_INCOMPATIBLE_EXCLUSIONS: &[KnownIncompatibleExclusion] =
    &[KnownIncompatibleExclusion {
        codex_version: "0.152.0",
        operating_system: OperatingSystem::Windows,
        surface: Surface::LocalCliLauncher,
        reason: "precedes the inspected native Windows hook-adapter baseline",
    }];

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EligibilityReason {
    UnsupportedPlatform,
    UnsupportedSurface,
    UnsupportedProtocol,
    KnownIncompatible,
    MalformedOrPrereleaseVersion,
    BelowAdapterBaseline,
    StrictRequiresVerifiedTuple,
}

impl EligibilityReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported platform or hosted runtime",
            Self::UnsupportedSurface => "unsupported Codex surface",
            Self::UnsupportedProtocol => "unsupported hook protocol adapter",
            Self::KnownIncompatible => "explicitly excluded Codex version",
            Self::MalformedOrPrereleaseVersion => "unknown, malformed, or prerelease version",
            Self::BelowAdapterBaseline => "older than the inspected platform adapter baseline",
            Self::StrictRequiresVerifiedTuple => {
                "strict compatibility policy requires a reviewed exact tuple"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionEligibility {
    Verified(&'static CompatibilityEntry),
    Experimental { baseline: &'static str },
    Unarmed(EligibilityReason),
}

impl VersionEligibility {
    pub const fn is_eligible(self) -> bool {
        matches!(self, Self::Verified(_) | Self::Experimental { .. })
    }

    pub const fn status(self) -> &'static str {
        match self {
            Self::Verified(_) => VerificationStatus::Verified.as_str(),
            Self::Experimental { .. } => VerificationStatus::Experimental.as_str(),
            Self::Unarmed(reason) => reason.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeSchemaStatus {
    Supported,
    UnsupportedPlatform,
    UnsupportedSurface,
    UnsupportedProtocol,
    UnsupportedVersion,
    UnsupportedTool,
}

impl RuntimeSchemaStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported PermissionRequest/Bash schema",
            Self::UnsupportedPlatform => "unsupported platform or hosted runtime",
            Self::UnsupportedSurface => "unsupported Codex surface",
            Self::UnsupportedProtocol => "unsupported hook protocol adapter",
            Self::UnsupportedVersion => "version is outside the runtime adapter baseline",
            Self::UnsupportedTool => "tool schema is not the reviewed Bash shape",
        }
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

fn stable_version(version: &str) -> Option<[u64; 3]> {
    let mut parts = version.split('.');
    let values = [parts.next()?, parts.next()?, parts.next()?];
    if parts.next().is_some()
        || values.iter().any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some([
        values[0].parse().ok()?,
        values[1].parse().ok()?,
        values[2].parse().ok()?,
    ])
}

fn version_at_least(version: &str, baseline: &str) -> bool {
    stable_version(version)
        .zip(stable_version(baseline))
        .is_some_and(|(version, baseline)| version >= baseline)
}

fn adapter_baseline(operating_system: OperatingSystem) -> Option<&'static str> {
    match operating_system {
        OperatingSystem::Linux if !is_wsl_runtime() => Some(LINUX_ADAPTER_BASELINE),
        OperatingSystem::Windows => Some(WINDOWS_ADAPTER_BASELINE),
        OperatingSystem::MacOs | OperatingSystem::Other => None,
        OperatingSystem::Linux => None,
    }
}

fn known_incompatible(request: CompatibilityRequest<'_>) -> Option<&'static str> {
    KNOWN_INCOMPATIBLE_EXCLUSIONS
        .iter()
        .find(|exclusion| {
            exclusion.codex_version == request.codex_version
                && exclusion.operating_system == request.operating_system
                && exclusion.surface == request.surface
        })
        .map(|exclusion| exclusion.reason)
}

pub fn version_eligibility(request: CompatibilityRequest<'_>, strict: bool) -> VersionEligibility {
    if request.surface != Surface::LocalCliLauncher {
        return VersionEligibility::Unarmed(EligibilityReason::UnsupportedSurface);
    }
    if request.hook_protocol != SUPPORTED_HOOK_PROTOCOL {
        return VersionEligibility::Unarmed(EligibilityReason::UnsupportedProtocol);
    }
    let Some(baseline) = adapter_baseline(request.operating_system) else {
        return VersionEligibility::Unarmed(EligibilityReason::UnsupportedPlatform);
    };
    if known_incompatible(request).is_some() {
        return VersionEligibility::Unarmed(EligibilityReason::KnownIncompatible);
    }
    let Some(version) = stable_version(request.codex_version) else {
        return VersionEligibility::Unarmed(EligibilityReason::MalformedOrPrereleaseVersion);
    };

    if let Some(entry) = verified_entry(request) {
        return VersionEligibility::Verified(entry);
    }
    if strict {
        return VersionEligibility::Unarmed(EligibilityReason::StrictRequiresVerifiedTuple);
    }
    let baseline_version = stable_version(baseline).expect("static adapter baseline is semantic");
    if version >= baseline_version {
        VersionEligibility::Experimental { baseline }
    } else {
        VersionEligibility::Unarmed(EligibilityReason::BelowAdapterBaseline)
    }
}

pub fn runtime_request_schema(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
    tool_name: &str,
) -> RuntimeSchemaStatus {
    if adapter_baseline(operating_system).is_none() {
        return RuntimeSchemaStatus::UnsupportedPlatform;
    }
    if surface != Surface::LocalCliLauncher {
        return RuntimeSchemaStatus::UnsupportedSurface;
    }
    if hook_protocol != SUPPORTED_HOOK_PROTOCOL {
        return RuntimeSchemaStatus::UnsupportedProtocol;
    }
    if tool_name != "Bash" {
        return RuntimeSchemaStatus::UnsupportedTool;
    }
    let request = CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface,
        hook_protocol,
    };
    if known_incompatible(request).is_some() {
        return RuntimeSchemaStatus::UnsupportedVersion;
    }
    let version_supported = verified_entry(request).is_some()
        || adapter_baseline(operating_system)
            .is_some_and(|baseline| version_at_least(version, baseline));
    if version_supported {
        RuntimeSchemaStatus::Supported
    } else {
        RuntimeSchemaStatus::UnsupportedVersion
    }
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

#[allow(dead_code)]
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

#[allow(dead_code)]
pub fn observed_tool_supported(
    version: &str,
    operating_system: OperatingSystem,
    surface: Surface,
    hook_protocol: &str,
    tool_name: &str,
) -> bool {
    matches!(
        runtime_request_schema(version, operating_system, surface, hook_protocol, tool_name),
        RuntimeSchemaStatus::Supported
    )
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
    } else if let Some(entry) = candidate_entry(request) {
        entry.verification_status.as_str()
    } else {
        version_eligibility(request, false).status()
    }
}

pub fn resolved_verification_target(version: &str) -> Option<VerificationTarget> {
    let operating_system = OperatingSystem::current();
    let request = CompatibilityRequest {
        codex_version: version,
        operating_system,
        surface: Surface::LocalCliLauncher,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
    };
    if !version_eligibility(request, false).is_eligible() {
        return None;
    }
    match operating_system {
        OperatingSystem::Linux | OperatingSystem::Windows => {}
        OperatingSystem::MacOs | OperatingSystem::Other => return None,
    }
    let command = verification_probe_command();
    Some(VerificationTarget {
        version: version.to_owned(),
        operating_system,
        surface: Surface::LocalCliLauncher,
        hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        observed_tool_type: "Bash",
        command,
    })
}

pub fn verification_version_matches(actual: &str, target: &VerificationTarget) -> bool {
    actual == target.version
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

    fn request(version: &str, operating_system: OperatingSystem) -> CompatibilityRequest<'_> {
        CompatibilityRequest {
            codex_version: version,
            operating_system,
            surface: Surface::LocalCliLauncher,
            hook_protocol: SUPPORTED_HOOK_PROTOCOL,
        }
    }

    #[test]
    fn registry_preserves_verified_entries_and_requested_experimental_targets() {
        assert_eq!(COMPATIBILITY_REGISTRY.len(), 6);
        assert!(verified_hook_support_for(
            "0.151.0",
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        assert!(!verified_hook_support_for(
            "0.153.0",
            OperatingSystem::Linux,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        assert!(verified_hook_support_for(
            "0.153.2",
            OperatingSystem::Windows,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        assert!(matches!(
            version_eligibility(request("0.153.2", OperatingSystem::Windows), true),
            VersionEligibility::Verified(entry) if entry.codex_version == "0.153.2"
        ));
        assert!(verified_hook_support_for(
            WINDOWS_NEWLY_VERIFIED_VERSION,
            OperatingSystem::Windows,
            Surface::LocalCliLauncher,
            SUPPORTED_HOOK_PROTOCOL
        ));
        assert!(matches!(
            version_eligibility(
                request(WINDOWS_NEWLY_VERIFIED_VERSION, OperatingSystem::Windows),
                true
            ),
            VersionEligibility::Verified(entry)
                if entry.codex_version == WINDOWS_NEWLY_VERIFIED_VERSION
        ));
        assert_eq!(
            version_eligibility(request("0.153.0", OperatingSystem::Linux), false),
            VersionEligibility::Experimental {
                baseline: LINUX_ADAPTER_BASELINE
            }
        );
        assert_eq!(
            COMPATIBILITY_REGISTRY
                .iter()
                .find(|entry| entry.codex_version == "0.153.4")
                .expect("Linux requested target")
                .verification_status,
            VerificationStatus::Experimental
        );
        assert_eq!(
            COMPATIBILITY_REGISTRY
                .iter()
                .find(|entry| entry.codex_version == WINDOWS_NEWLY_VERIFIED_VERSION)
                .expect("Windows newly verified target")
                .verification_status,
            VerificationStatus::Verified
        );
    }

    #[test]
    fn automatic_policy_attempts_newer_stable_versions_but_strict_does_not() {
        assert!(matches!(
            version_eligibility(request("0.153.4", OperatingSystem::Linux), false),
            VersionEligibility::Experimental { .. }
        ));
        assert!(matches!(
            version_eligibility(request("0.999.0", OperatingSystem::Linux), false),
            VersionEligibility::Experimental { .. }
        ));
        assert!(matches!(
            version_eligibility(
                request(WINDOWS_NEWLY_VERIFIED_VERSION, OperatingSystem::Windows),
                false
            ),
            VersionEligibility::Verified(_)
        ));
        assert!(matches!(
            version_eligibility(request("0.153.4", OperatingSystem::Linux), true),
            VersionEligibility::Unarmed(EligibilityReason::StrictRequiresVerifiedTuple)
        ));
    }

    #[test]
    fn malformed_prerelease_old_and_known_incompatible_versions_are_unarmed() {
        for version in ["", "0.153.4-rc.1", "0.153", "v0.153.4", "0.152.9"] {
            assert!(matches!(
                version_eligibility(request(version, OperatingSystem::Linux), false),
                VersionEligibility::Unarmed(_)
            ));
        }
        assert_eq!(
            version_eligibility(request("0.152.0", OperatingSystem::Windows), false),
            VersionEligibility::Unarmed(EligibilityReason::KnownIncompatible)
        );
    }

    #[test]
    fn runtime_schema_is_separate_from_version_review_status() {
        if cfg!(unix) {
            assert_eq!(
                runtime_request_schema(
                    "0.153.4",
                    OperatingSystem::Linux,
                    Surface::LocalCliLauncher,
                    SUPPORTED_HOOK_PROTOCOL,
                    "Bash"
                ),
                RuntimeSchemaStatus::Supported
            );
            assert_eq!(
                runtime_request_schema(
                    "0.153.4",
                    OperatingSystem::Linux,
                    Surface::LocalCliLauncher,
                    SUPPORTED_HOOK_PROTOCOL,
                    "Mcp"
                ),
                RuntimeSchemaStatus::UnsupportedTool
            );
            assert_eq!(
                runtime_request_schema(
                    "0.153.4-rc.1",
                    OperatingSystem::Linux,
                    Surface::LocalCliLauncher,
                    SUPPORTED_HOOK_PROTOCOL,
                    "Bash"
                ),
                RuntimeSchemaStatus::UnsupportedVersion
            );
        }
    }

    #[test]
    fn unsupported_platforms_and_surfaces_are_unarmed() {
        assert!(matches!(
            version_eligibility(request("0.999.0", OperatingSystem::MacOs), false),
            VersionEligibility::Unarmed(EligibilityReason::UnsupportedPlatform)
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
            assert!(matches!(
                version_eligibility(
                    CompatibilityRequest {
                        surface,
                        ..request("0.999.0", OperatingSystem::Linux)
                    },
                    false
                ),
                VersionEligibility::Unarmed(EligibilityReason::UnsupportedSurface)
            ));
        }
    }

    #[test]
    fn verification_target_is_derived_from_the_installed_version() {
        if cfg!(unix) {
            let target = resolved_verification_target("0.153.4").expect("eligible target");
            assert_eq!(target.version, "0.153.4");
            assert_eq!(target.command, "curl -I https://example.com");
            assert!(!verification_version_matches("0.153.5", &target));
        }
    }

    #[test]
    fn candidate_is_not_verified() {
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
}
