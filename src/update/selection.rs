//! Pure, deterministic selection of an applicable authenticated release.
//!
//! Selection consumes only the crate-private TUF-authenticated manifest
//! wrapper. It does not fetch, install, execute, activate, or authorize
//! anything, and it does not modify the existing hook compatibility registry.

use std::{cmp::Reverse, collections::BTreeSet};

use crate::{
    cli::CompatibilityMode,
    update::manifest::{
        CompatibilityArchitecture, CompatibilityEligibility, CompatibilityOperatingSystem,
        CompatibilitySurface, ExperimentalBasis, Libc, ReleaseAsset, ReleaseManifest, ReleaseNotes,
        StableVersion, TargetArchitecture, TargetOperatingSystem, TufAuthenticatedManifest,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    Windows { major: u16, year: u16, half: u8 },
    LinuxGlibc { major: u16, minor: u16 },
    Unknown,
}

impl RuntimeEnvironment {
    pub const fn windows(major: u16, year: u16, half: u8) -> Self {
        Self::Windows { major, year, half }
    }

    pub const fn linux_glibc(major: u16, minor: u16) -> Self {
        Self::LinuxGlibc { major, minor }
    }

    pub const fn unknown() -> Self {
        Self::Unknown
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionInput {
    pub installed_autoapprover_version: StableVersion,
    pub codex_version: StableVersion,
    pub operating_system: TargetOperatingSystem,
    pub architecture: TargetArchitecture,
    pub runtime: RuntimeEnvironment,
    pub surface: CompatibilitySurface,
    pub compatibility_mode: CompatibilityMode,
}

impl SelectionInput {
    pub fn from_versions(
        installed_autoapprover_version: &str,
        codex_version: &str,
        operating_system: TargetOperatingSystem,
        architecture: TargetArchitecture,
        runtime: RuntimeEnvironment,
        surface: CompatibilitySurface,
        compatibility_mode: CompatibilityMode,
    ) -> Result<Self, SelectionInputError> {
        Ok(Self {
            installed_autoapprover_version: StableVersion::parse(installed_autoapprover_version)
                .map_err(|_| SelectionInputError::MalformedInstalledAutoapproverVersion)?,
            codex_version: StableVersion::parse(codex_version)
                .map_err(|_| SelectionInputError::MalformedCodexVersion)?,
            operating_system,
            architecture,
            runtime,
            surface,
            compatibility_mode,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionInputError {
    MalformedInstalledAutoapproverVersion,
    MalformedCodexVersion,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SelectionRejectionReason {
    EmptyCatalog,
    DuplicateReleaseVersion,
    ConflictingAssetIdentity,
    AmbiguousAsset,
    AmbiguousCompatibility,
    NotNewerThanInstalled,
    UnsupportedPlatform,
    UnsupportedArchitecture,
    UnknownRuntime,
    UnsupportedRuntime,
    MalformedRuntimeRequirement,
    RuntimeBelowMinimum,
    CompatibilityExcluded,
    CompatibilityUnavailable,
    StrictRequiresReviewed,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CandidateRejection {
    pub release_version: StableVersion,
    pub reason: SelectionRejectionReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectedCompatibility {
    Reviewed { evidence_ref: String },
    Experimental { basis: ExperimentalBasis },
}

impl SelectedCompatibility {
    pub const fn status(&self) -> &'static str {
        match self {
            Self::Reviewed { .. } => "reviewed",
            Self::Experimental { .. } => "experimental",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicabilityExplanation {
    pub current_autoapprover_version: StableVersion,
    pub new_autoapprover_version: StableVersion,
    pub compatibility: SelectedCompatibility,
    pub release_notes: ReleaseNotes,
}

pub struct SelectedRelease<'a> {
    release: &'a TufAuthenticatedManifest,
    asset: &'a ReleaseAsset,
    compatibility: SelectedCompatibility,
    explanation: ApplicabilityExplanation,
}

impl<'a> SelectedRelease<'a> {
    pub fn manifest(&self) -> &ReleaseManifest {
        self.release.manifest()
    }

    pub fn asset(&self) -> &ReleaseAsset {
        self.asset
    }

    pub fn compatibility(&self) -> &SelectedCompatibility {
        &self.compatibility
    }

    pub fn explanation(&self) -> &ApplicabilityExplanation {
        &self.explanation
    }
}

pub enum SelectionOutcome<'a> {
    Selected(SelectedRelease<'a>),
    NoApplicable { rejections: Vec<CandidateRejection> },
    Rejected { reason: SelectionRejectionReason },
}

pub fn select_applicable<'a>(
    candidates: &'a [TufAuthenticatedManifest],
    input: &SelectionInput,
) -> SelectionOutcome<'a> {
    if candidates.is_empty() {
        return SelectionOutcome::Rejected {
            reason: SelectionRejectionReason::EmptyCatalog,
        };
    }
    if let Err(reason) = validate_catalog_ambiguity(candidates) {
        return SelectionOutcome::Rejected { reason };
    }

    let mut selected = Vec::new();
    let mut rejections = Vec::new();
    for candidate in candidates {
        let manifest = candidate.manifest();
        let release_version = manifest.release_version.clone();
        if release_version <= input.installed_autoapprover_version {
            rejections.push(CandidateRejection {
                release_version,
                reason: SelectionRejectionReason::NotNewerThanInstalled,
            });
            continue;
        }

        let asset = match select_asset(&manifest.assets, input) {
            Ok(asset) => asset,
            Err(reason) => {
                rejections.push(CandidateRejection {
                    release_version,
                    reason,
                });
                continue;
            }
        };
        let compatibility = match select_compatibility(&manifest.compatibility, input) {
            Ok(compatibility) => compatibility,
            Err(reason) => {
                rejections.push(CandidateRejection {
                    release_version,
                    reason,
                });
                continue;
            }
        };
        let explanation = ApplicabilityExplanation {
            current_autoapprover_version: input.installed_autoapprover_version.clone(),
            new_autoapprover_version: manifest.release_version.clone(),
            compatibility: compatibility.clone(),
            release_notes: manifest.release_notes.clone(),
        };
        selected.push(SelectedRelease {
            release: candidate,
            asset,
            compatibility,
            explanation,
        });
    }

    if selected.is_empty() {
        rejections.sort();
        return SelectionOutcome::NoApplicable { rejections };
    }

    selected.sort_by(|left, right| {
        left.manifest()
            .release_version
            .cmp(&right.manifest().release_version)
    });
    SelectionOutcome::Selected(selected.pop().expect("selected is non-empty"))
}

fn validate_catalog_ambiguity(
    candidates: &[TufAuthenticatedManifest],
) -> Result<(), SelectionRejectionReason> {
    let mut release_versions = BTreeSet::new();
    for candidate in candidates {
        let manifest = candidate.manifest();
        if !release_versions.insert(manifest.release_version.clone()) {
            return Err(SelectionRejectionReason::DuplicateReleaseVersion);
        }
        validate_manifest_ambiguity(manifest)?;
    }
    Ok(())
}

fn validate_manifest_ambiguity(manifest: &ReleaseManifest) -> Result<(), SelectionRejectionReason> {
    let mut asset_names = BTreeSet::new();
    let mut asset_identities = BTreeSet::new();
    for asset in &manifest.assets {
        if !asset_names.insert(asset.target_name.clone()) {
            return Err(SelectionRejectionReason::ConflictingAssetIdentity);
        }
        let identity = format!(
            "{:?}|{:?}|{}|{:?}|{:?}",
            asset.operating_system,
            asset.architecture,
            asset.runtime.minimum,
            asset.runtime.libc,
            asset.archive_format
        );
        if !asset_identities.insert(identity) {
            return Err(SelectionRejectionReason::ConflictingAssetIdentity);
        }
    }

    let mut compatibility_identities = BTreeSet::new();
    for record in &manifest.compatibility {
        let tuple = &record.tuple;
        let identity = format!(
            "{}|{:?}|{:?}|{:?}|{}|{}|{}|{}|{}",
            tuple.codex_version,
            tuple.operating_system,
            tuple.architecture,
            tuple.surface,
            tuple.hook_event,
            tuple.hook_protocol,
            tuple.required_tool,
            tuple.tool_input_schema,
            tuple.response_behavior
        );
        if !compatibility_identities.insert(identity) {
            return Err(SelectionRejectionReason::AmbiguousCompatibility);
        }
    }
    Ok(())
}

fn select_asset<'a>(
    assets: &'a [ReleaseAsset],
    input: &SelectionInput,
) -> Result<&'a ReleaseAsset, SelectionRejectionReason> {
    let platform_assets: Vec<_> = assets
        .iter()
        .filter(|asset| asset.operating_system == input.operating_system)
        .collect();
    if platform_assets.is_empty() {
        return Err(SelectionRejectionReason::UnsupportedPlatform);
    }
    let architecture_assets: Vec<_> = platform_assets
        .into_iter()
        .filter(|asset| asset.architecture == input.architecture)
        .collect();
    if architecture_assets.is_empty() {
        return Err(SelectionRejectionReason::UnsupportedArchitecture);
    }

    let mut applicable = Vec::new();
    for asset in architecture_assets {
        let minimum = parse_runtime_minimum(asset)?;
        if runtime_meets(&input.runtime, &input.operating_system, minimum)? {
            applicable.push((asset, minimum));
        }
    }
    if applicable.is_empty() {
        return Err(SelectionRejectionReason::RuntimeBelowMinimum);
    }
    applicable.sort_by_key(|entry| Reverse(entry.1));
    if applicable.len() > 1 && applicable[0].1 == applicable[1].1 {
        return Err(SelectionRejectionReason::AmbiguousAsset);
    }
    Ok(applicable[0].0)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RuntimeMinimum {
    Windows { major: u16, year: u16, half: u8 },
    LinuxGlibc { major: u16, minor: u16 },
}

fn parse_runtime_minimum(asset: &ReleaseAsset) -> Result<RuntimeMinimum, SelectionRejectionReason> {
    match asset.operating_system {
        TargetOperatingSystem::Windows if asset.runtime.libc.is_none() => {
            let Some(value) = asset.runtime.minimum.strip_prefix("windows-") else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let mut parts = value.split('-');
            let Some(major) = parse_decimal_u16(parts.next()) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let Some(release) = parts.next() else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            if parts.next().is_some() || release.len() != 4 {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            }
            let Some(year) = parse_decimal_u16(release.get(..2)) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let Some(half) = release.get(2..).and_then(|value| value.strip_prefix("h")) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let Some(half) = parse_decimal_u8(Some(half)) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            if !matches!(half, 1 | 2) {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            }
            Ok(RuntimeMinimum::Windows { major, year, half })
        }
        TargetOperatingSystem::Linux if asset.runtime.libc == Some(Libc::Glibc) => {
            let Some(value) = asset.runtime.minimum.strip_prefix("glibc-") else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let mut parts = value.split('.');
            let Some(major) = parse_decimal_u16(parts.next()) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            let Some(minor) = parse_decimal_u16(parts.next()) else {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            };
            if parts.next().is_some() {
                return Err(SelectionRejectionReason::MalformedRuntimeRequirement);
            }
            Ok(RuntimeMinimum::LinuxGlibc { major, minor })
        }
        _ => Err(SelectionRejectionReason::MalformedRuntimeRequirement),
    }
}

fn parse_decimal_u16(value: Option<&str>) -> Option<u16> {
    let value = value?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn parse_decimal_u8(value: Option<&str>) -> Option<u8> {
    let value = value?;
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn runtime_meets(
    runtime: &RuntimeEnvironment,
    operating_system: &TargetOperatingSystem,
    minimum: RuntimeMinimum,
) -> Result<bool, SelectionRejectionReason> {
    match (operating_system, runtime, minimum) {
        (_, RuntimeEnvironment::Unknown, _) => Err(SelectionRejectionReason::UnknownRuntime),
        (
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::Windows { major, year, half },
            RuntimeMinimum::Windows {
                major: minimum_major,
                year: minimum_year,
                half: minimum_half,
            },
        ) => {
            if !matches!(half, 1 | 2) {
                return Err(SelectionRejectionReason::UnknownRuntime);
            }
            Ok((*major, *year, *half) >= (minimum_major, minimum_year, minimum_half))
        }
        (
            TargetOperatingSystem::Linux,
            RuntimeEnvironment::LinuxGlibc { major, minor },
            RuntimeMinimum::LinuxGlibc {
                major: minimum_major,
                minor: minimum_minor,
            },
        ) => Ok((*major, *minor) >= (minimum_major, minimum_minor)),
        _ => Err(SelectionRejectionReason::UnsupportedRuntime),
    }
}

fn select_compatibility(
    records: &[crate::update::manifest::CompatibilityRecord],
    input: &SelectionInput,
) -> Result<SelectedCompatibility, SelectionRejectionReason> {
    let matching: Vec<_> = records
        .iter()
        .filter(|record| tuple_matches(&record.tuple, input))
        .collect();
    if matching.iter().any(|record| {
        matches!(
            record.eligibility,
            CompatibilityEligibility::Excluded { .. }
        )
    }) {
        return Err(SelectionRejectionReason::CompatibilityExcluded);
    }
    if matching.len() != 1 {
        return Err(if matching.is_empty() {
            SelectionRejectionReason::CompatibilityUnavailable
        } else {
            SelectionRejectionReason::AmbiguousCompatibility
        });
    }

    match &matching[0].eligibility {
        CompatibilityEligibility::Reviewed { evidence_ref } => {
            Ok(SelectedCompatibility::Reviewed {
                evidence_ref: evidence_ref.clone(),
            })
        }
        CompatibilityEligibility::Experimental { basis }
            if input.compatibility_mode == CompatibilityMode::Automatic =>
        {
            Ok(SelectedCompatibility::Experimental {
                basis: basis.clone(),
            })
        }
        CompatibilityEligibility::Experimental { .. } => {
            Err(SelectionRejectionReason::StrictRequiresReviewed)
        }
        CompatibilityEligibility::Excluded { .. } => {
            Err(SelectionRejectionReason::CompatibilityExcluded)
        }
    }
}

fn tuple_matches(
    tuple: &crate::update::manifest::CompatibilityTuple,
    input: &SelectionInput,
) -> bool {
    tuple.codex_version == input.codex_version
        && tuple.operating_system == compatibility_os(&input.operating_system)
        && tuple.architecture == CompatibilityArchitecture::X86_64
        && input.architecture == TargetArchitecture::X86_64
        && tuple.surface == input.surface
}

fn compatibility_os(operating_system: &TargetOperatingSystem) -> CompatibilityOperatingSystem {
    match operating_system {
        TargetOperatingSystem::Linux => CompatibilityOperatingSystem::Linux,
        TargetOperatingSystem::Windows => CompatibilityOperatingSystem::Windows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::manifest::{
        ParsedManifest, Sha256Digest, TufVerifiedTarget, parse_manifest,
    };
    use serde_json::Value;

    const VALID_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/distribution_manifest/valid.json"
    ));

    fn authenticated_manifest(
        release_version: &str,
        include_windows_compatibility: bool,
    ) -> TufAuthenticatedManifest {
        let mut value: Value = serde_json::from_str(VALID_FIXTURE).expect("fixture JSON");
        value["release_version"] = Value::String(release_version.to_owned());
        if !include_windows_compatibility {
            value["compatibility"] = Value::Array(
                value["compatibility"]
                    .as_array()
                    .expect("compatibility array")
                    .iter()
                    .filter(|record| record["tuple"]["operating_system"] == "linux")
                    .cloned()
                    .collect(),
            );
        }
        let bytes = serde_json::to_vec(&value).expect("synthetic manifest JSON");
        let parsed: ParsedManifest = parse_manifest(&bytes).expect("validated manifest");
        let target_name = parsed.manifest().manifest_target.clone();
        let target = TufVerifiedTarget::from_verified_metadata(
            target_name,
            bytes.len() as u64,
            Sha256Digest::from_bytes(&bytes),
        );
        parsed
            .authenticate_tuf(target)
            .expect("TUF-authenticated fixture")
    }

    fn input(
        installed: &str,
        codex: &str,
        operating_system: TargetOperatingSystem,
        runtime: RuntimeEnvironment,
        compatibility_mode: CompatibilityMode,
    ) -> SelectionInput {
        SelectionInput::from_versions(
            installed,
            codex,
            operating_system,
            TargetArchitecture::X86_64,
            runtime,
            CompatibilitySurface::LocalCliLauncher,
            compatibility_mode,
        )
        .expect("valid selection input")
    }

    fn selected_version(outcome: SelectionOutcome<'_>) -> String {
        match outcome {
            SelectionOutcome::Selected(selected) => selected.manifest().release_version.to_string(),
            other => panic!(
                "expected selection, got {}",
                match other {
                    SelectionOutcome::NoApplicable { .. } => "no applicable",
                    SelectionOutcome::Rejected { .. } => "rejected",
                    SelectionOutcome::Selected(_) => "selected",
                }
            ),
        }
    }

    #[test]
    fn selects_numeric_newest_release_not_input_order() {
        let nine = authenticated_manifest("0.9.0", true);
        let ten = authenticated_manifest("0.10.0", true);
        let selection_input = input(
            "0.8.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        assert_eq!(
            selected_version(select_applicable(&[nine, ten], &selection_input)),
            "0.10.0"
        );
    }

    #[test]
    fn skips_newer_incompatible_release_and_selects_older_applicable_release() {
        let applicable = authenticated_manifest("0.11.0", true);
        let incompatible = authenticated_manifest("0.12.0", false);
        let selection_input = input(
            "0.10.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        assert_eq!(
            selected_version(select_applicable(
                &[incompatible, applicable],
                &selection_input
            )),
            "0.11.0"
        );
    }

    #[test]
    fn automatic_selects_experimental_but_strict_requires_reviewed() {
        let candidate = authenticated_manifest("0.3.0", true);
        let automatic = input(
            "0.2.0",
            "0.153.0",
            TargetOperatingSystem::Linux,
            RuntimeEnvironment::linux_glibc(2, 31),
            CompatibilityMode::Automatic,
        );
        match select_applicable(std::slice::from_ref(&candidate), &automatic) {
            SelectionOutcome::Selected(selected) => {
                assert_eq!(selected.compatibility().status(), "experimental");
            }
            _ => panic!("automatic mode should allow explicit experimental eligibility"),
        }

        let strict = SelectionInput {
            compatibility_mode: CompatibilityMode::Strict,
            ..automatic
        };
        assert!(matches!(
            select_applicable(std::slice::from_ref(&candidate), &strict),
            SelectionOutcome::NoApplicable { ref rejections }
                if rejections.iter().any(|rejection| {
                    rejection.reason == SelectionRejectionReason::StrictRequiresReviewed
                })
        ));
    }

    #[test]
    fn exact_exclusion_overrides_automatic_experimental_policy() {
        let candidate = authenticated_manifest("0.3.0", true);
        let selection_input = input(
            "0.2.0",
            "0.152.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        let mut overlapping_records = candidate.manifest().compatibility.clone();
        let mut experimental = overlapping_records
            .iter()
            .find(|record| {
                record.tuple.codex_version
                    == StableVersion::parse("0.152.0").expect("stable version")
            })
            .expect("excluded tuple")
            .clone();
        experimental.eligibility = CompatibilityEligibility::Experimental {
            basis: ExperimentalBasis::CapabilityProbeOnly,
        };
        overlapping_records.push(experimental);
        assert_eq!(
            select_compatibility(&overlapping_records, &selection_input),
            Err(SelectionRejectionReason::CompatibilityExcluded)
        );
        assert!(matches!(
            select_applicable(std::slice::from_ref(&candidate), &selection_input),
            SelectionOutcome::NoApplicable { ref rejections }
                if rejections.iter().any(|rejection| {
                    rejection.reason == SelectionRejectionReason::CompatibilityExcluded
                })
        ));
    }

    #[test]
    fn runtime_floor_and_unknown_runtime_are_rejected() {
        let windows = authenticated_manifest("0.3.0", true);
        let below = input(
            "0.2.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 21, 2),
            CompatibilityMode::Automatic,
        );
        assert!(matches!(
            select_applicable(std::slice::from_ref(&windows), &below),
            SelectionOutcome::NoApplicable { ref rejections }
                if rejections.iter().any(|rejection| {
                    rejection.reason == SelectionRejectionReason::RuntimeBelowMinimum
                })
        ));

        let unknown = SelectionInput {
            runtime: RuntimeEnvironment::unknown(),
            ..below
        };
        assert!(matches!(
            select_applicable(std::slice::from_ref(&windows), &unknown),
            SelectionOutcome::NoApplicable { ref rejections }
                if rejections.iter().any(|rejection| {
                    rejection.reason == SelectionRejectionReason::UnknownRuntime
                })
        ));
    }

    #[test]
    fn empty_catalog_current_release_and_downgrade_are_not_updates() {
        let selection_input = input(
            "0.3.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        assert!(matches!(
            select_applicable(&[], &selection_input),
            SelectionOutcome::Rejected {
                reason: SelectionRejectionReason::EmptyCatalog
            }
        ));

        let current = authenticated_manifest("0.3.0", true);
        let older = authenticated_manifest("0.2.0", true);
        assert!(matches!(
            select_applicable(&[current, older], &selection_input),
            SelectionOutcome::NoApplicable { ref rejections }
                if rejections.iter().all(|rejection| {
                    rejection.reason == SelectionRejectionReason::NotNewerThanInstalled
                })
        ));
    }

    #[test]
    fn duplicate_release_versions_are_rejected() {
        let first = authenticated_manifest("0.3.0", true);
        let second = authenticated_manifest("0.3.0", true);
        let selection_input = input(
            "0.2.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        assert!(matches!(
            select_applicable(&[first, second], &selection_input),
            SelectionOutcome::Rejected {
                reason: SelectionRejectionReason::DuplicateReleaseVersion
            }
        ));
    }

    #[test]
    fn permutations_have_identical_selection_results() {
        let nine = authenticated_manifest("0.9.0", true);
        let ten = authenticated_manifest("0.10.0", true);
        let selection_input = input(
            "0.8.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        let forward_candidates = [nine, ten];
        let forward = select_applicable(&forward_candidates, &selection_input);

        let nine = authenticated_manifest("0.9.0", true);
        let ten = authenticated_manifest("0.10.0", true);
        let reverse_candidates = [ten, nine];
        let reverse = select_applicable(&reverse_candidates, &selection_input);
        assert_eq!(selected_version(forward), selected_version(reverse));
    }

    #[test]
    fn duplicate_records_and_equal_assets_are_rejected_without_input_order() {
        let candidate = authenticated_manifest("0.3.0", true);
        let mut duplicate_asset_manifest = candidate.manifest().clone();
        duplicate_asset_manifest
            .assets
            .push(duplicate_asset_manifest.assets[0].clone());
        assert_eq!(
            validate_manifest_ambiguity(&duplicate_asset_manifest),
            Err(SelectionRejectionReason::ConflictingAssetIdentity)
        );

        let mut duplicate_compatibility_manifest = candidate.manifest().clone();
        duplicate_compatibility_manifest
            .compatibility
            .push(duplicate_compatibility_manifest.compatibility[0].clone());
        assert_eq!(
            validate_manifest_ambiguity(&duplicate_compatibility_manifest),
            Err(SelectionRejectionReason::AmbiguousCompatibility)
        );

        let selection_input = input(
            "0.2.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        let mut equal_assets = candidate.manifest().assets.clone();
        equal_assets.push(equal_assets[1].clone());
        assert_eq!(
            select_asset(&equal_assets, &selection_input),
            Err(SelectionRejectionReason::AmbiguousAsset)
        );
    }

    #[test]
    fn malformed_codex_versions_are_rejected_before_selection() {
        assert_eq!(
            SelectionInput::from_versions(
                "0.1.0",
                "0.10.0-beta",
                TargetOperatingSystem::Windows,
                TargetArchitecture::X86_64,
                RuntimeEnvironment::windows(10, 22, 2),
                CompatibilitySurface::LocalCliLauncher,
                CompatibilityMode::Automatic,
            ),
            Err(SelectionInputError::MalformedCodexVersion)
        );
    }

    #[test]
    fn selected_explanation_and_registry_are_read_only() {
        let candidate = authenticated_manifest("0.3.0", true);
        let selection_input = input(
            "0.2.0",
            "0.154.0",
            TargetOperatingSystem::Windows,
            RuntimeEnvironment::windows(10, 22, 2),
            CompatibilityMode::Automatic,
        );
        let registry_len = crate::compatibility::COMPATIBILITY_REGISTRY.len();
        match select_applicable(std::slice::from_ref(&candidate), &selection_input) {
            SelectionOutcome::Selected(selected) => {
                assert_eq!(
                    selected.explanation().new_autoapprover_version.to_string(),
                    "0.3.0"
                );
                assert_eq!(selected.explanation().compatibility.status(), "reviewed");
                assert_eq!(
                    selected.explanation().release_notes.url,
                    "https://example.invalid/releases/0.2.0"
                );
            }
            _ => panic!("expected selected release"),
        }
        assert_eq!(
            crate::compatibility::COMPATIBILITY_REGISTRY.len(),
            registry_len
        );
    }
}
