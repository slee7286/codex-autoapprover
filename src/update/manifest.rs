//! Strict, descriptive release-manifest schema for the future updater.
//!
//! A parsed manifest is untrusted application metadata. It becomes an
//! TufAuthenticatedManifest only when a later TUF adapter supplies a
//! crate-private proof for the exact manifest target and bytes. This module
//! does not implement signatures, hashing, network access, release selection,
//! installation, or compatibility arming.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SUPPORTED_MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
pub const MAX_ASSET_COUNT: usize = 16;
pub const MAX_COMPATIBILITY_RECORD_COUNT: usize = 128;
pub const MAX_ASSET_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 4096;
const MAX_TARGET_NAME_BYTES: usize = 512;
const MAX_EVIDENCE_REF_BYTES: usize = 512;
const RELEASE_REPOSITORY: &str = "slee7286/codex-autoapprover";
const HTTPS_PREFIX: &str = "https://";
const SHA256_HEX_LENGTH: usize = 64;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("release manifest is {actual} bytes; maximum is {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid release manifest JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported release manifest schema version {0}; supported version is {SUPPORTED_MANIFEST_SCHEMA_VERSION}"
    )]
    UnsupportedSchemaVersion(u32),
    #[error("invalid release manifest: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct StableVersion {
    major: u64,
    minor: u64,
    patch: u64,
}

impl StableVersion {
    pub fn parse(value: &str) -> Result<Self, ManifestError> {
        let mut split = value.split('.');
        let parts = [split.next(), split.next(), split.next()];
        if parts.iter().any(Option::is_none) || split.next().is_some() {
            return Err(ManifestError::Invalid(format!(
                "version {value:?} must be exactly major.minor.patch"
            )));
        }
        let parse_component = |part: &str| {
            if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
                return Err(ManifestError::Invalid(format!(
                    "version {value:?} has an invalid numeric component"
                )));
            }
            part.parse::<u64>().map_err(|_| {
                ManifestError::Invalid(format!(
                    "version {value:?} has an invalid numeric component"
                ))
            })
        };
        let major = parse_component(parts[0].expect("checked version component count"))?;
        let minor = parse_component(parts[1].expect("checked version component count"))?;
        let patch = parse_component(parts[2].expect("checked version component count"))?;
        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for StableVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl Serialize for StableVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for StableVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    fn from_bytes(value: &[u8]) -> Self {
        let digest: [u8; 32] = Sha256::digest(value).into();
        Self(digest)
    }

    pub fn parse(value: &str) -> Result<Self, ManifestError> {
        if value.len() != SHA256_HEX_LENGTH
            || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            || value.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(ManifestError::Invalid(
                "sha256 must be exactly 64 lowercase hexadecimal characters".into(),
            ));
        }
        let mut digest = [0_u8; 32];
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        debug_assert!(remainder.is_empty());
        for (index, pair) in pairs.iter().enumerate() {
            digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(Self(digest))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(SHA256_HEX_LENGTH);
        for byte in self.0 {
            encoded.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            encoded.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetOperatingSystem {
    Linux,
    Windows,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetArchitecture {
    #[serde(rename = "x86_64")]
    X86_64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveFormat {
    Zip,
    TarGz,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Libc {
    Glibc,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityOperatingSystem {
    Linux,
    MacOs,
    Windows,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityArchitecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilitySurface {
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

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExperimentalBasis {
    StableAtOrAboveAdapterBaseline,
    CapabilityProbeOnly,
    RequestedTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRequirements {
    pub minimum: String,
    pub libc: Option<Libc>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseNotes {
    pub title: String,
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssetProvenance {
    pub source_repository: String,
    pub source_revision: String,
    pub build_workflow: String,
    pub build_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub target_name: String,
    pub operating_system: TargetOperatingSystem,
    pub architecture: TargetArchitecture,
    pub runtime: RuntimeRequirements,
    pub archive_format: ArchiveFormat,
    pub length: u64,
    pub sha256: Sha256Digest,
    pub download_origin: String,
    pub provenance: AssetProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityTuple {
    pub codex_version: StableVersion,
    pub operating_system: CompatibilityOperatingSystem,
    pub architecture: CompatibilityArchitecture,
    pub surface: CompatibilitySurface,
    pub hook_event: String,
    pub hook_protocol: String,
    pub required_tool: String,
    pub tool_input_schema: String,
    pub response_behavior: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields, tag = "status")]
pub enum CompatibilityEligibility {
    #[serde(rename = "reviewed")]
    Reviewed { evidence_ref: String },
    #[serde(rename = "experimental")]
    Experimental { basis: ExperimentalBasis },
    #[serde(rename = "excluded")]
    Excluded { reason: String },
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityRecord {
    pub tuple: CompatibilityTuple,
    pub eligibility: CompatibilityEligibility,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub manifest_target: String,
    pub release_version: StableVersion,
    pub release_notes: ReleaseNotes,
    pub assets: Vec<ReleaseAsset>,
    pub compatibility: Vec<CompatibilityRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedManifest {
    manifest: ReleaseManifest,
    byte_length: usize,
    sha256: Sha256Digest,
}

impl ParsedManifest {
    pub fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub fn byte_length(&self) -> usize {
        self.byte_length
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, ManifestError> {
        canonical_json(&self.manifest)
    }

    pub(crate) fn authenticate_tuf(
        self,
        target: TufVerifiedTarget,
    ) -> Result<TufAuthenticatedManifest, ManifestError> {
        if target.target_name != self.manifest.manifest_target {
            return Err(ManifestError::Invalid(
                "TUF target name does not match manifest_target".into(),
            ));
        }
        if target.length != self.byte_length as u64 {
            return Err(ManifestError::Invalid(
                "TUF target length does not match parsed manifest bytes".into(),
            ));
        }
        if target.sha256 != self.sha256 {
            return Err(ManifestError::Invalid(
                "TUF target hash does not match parsed manifest bytes".into(),
            ));
        }
        Ok(TufAuthenticatedManifest {
            manifest: self.manifest,
            tuf_target: target,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TufVerifiedTarget {
    target_name: String,
    length: u64,
    sha256: Sha256Digest,
}

impl TufVerifiedTarget {
    /// The future TUF adapter must call this only after the TUF client has
    /// verified the target metadata and exact target bytes. It is crate-private
    /// so parsing callers cannot claim authenticity directly.
    pub(crate) fn from_verified_metadata(
        target_name: String,
        length: u64,
        sha256: Sha256Digest,
    ) -> Self {
        Self {
            target_name,
            length,
            sha256,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TufAuthenticatedManifest {
    manifest: ReleaseManifest,
    tuf_target: TufVerifiedTarget,
}

impl TufAuthenticatedManifest {
    pub(crate) fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub(crate) fn tuf_target(&self) -> &TufVerifiedTarget {
        &self.tuf_target
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ParsedManifest, ManifestError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_MANIFEST_BYTES,
        });
    }
    reject_duplicate_json_keys(bytes)?;
    let manifest: ReleaseManifest = serde_json::from_slice(bytes)?;
    validate_manifest(&manifest)?;
    Ok(ParsedManifest {
        manifest,
        byte_length: bytes.len(),
        sha256: Sha256Digest::from_bytes(bytes),
    })
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != SUPPORTED_MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedSchemaVersion(
            manifest.schema_version,
        ));
    }
    validate_target_name(&manifest.manifest_target)?;
    validate_release_notes(&manifest.release_notes)?;
    if manifest.assets.is_empty() || manifest.assets.len() > MAX_ASSET_COUNT {
        return Err(ManifestError::Invalid(format!(
            "assets must contain between 1 and {MAX_ASSET_COUNT} records"
        )));
    }
    if manifest.compatibility.is_empty()
        || manifest.compatibility.len() > MAX_COMPATIBILITY_RECORD_COUNT
    {
        return Err(ManifestError::Invalid(format!(
            "compatibility must contain between 1 and {MAX_COMPATIBILITY_RECORD_COUNT} records"
        )));
    }

    let mut asset_names = BTreeSet::new();
    let mut asset_identities = BTreeSet::new();
    for asset in &manifest.assets {
        validate_asset(asset)?;
        if !asset_names.insert(asset.target_name.clone()) {
            return Err(ManifestError::Invalid(format!(
                "duplicate asset target_name {:?}",
                asset.target_name
            )));
        }
        let identity = format!(
            "{:?}|{:?}|{}|{:?}",
            asset.operating_system, asset.architecture, asset.runtime.minimum, asset.archive_format
        );
        if !asset_identities.insert(identity) {
            return Err(ManifestError::Invalid(
                "duplicate asset identity for target platform/runtime/archive".into(),
            ));
        }
    }

    let mut compatibility_identities = BTreeSet::new();
    for record in &manifest.compatibility {
        validate_compatibility(record)?;
        let identity = compatibility_identity(&record.tuple);
        if !compatibility_identities.insert(identity) {
            return Err(ManifestError::Invalid(
                "duplicate or contradictory compatibility tuple".into(),
            ));
        }
    }
    Ok(())
}

fn validate_asset(asset: &ReleaseAsset) -> Result<(), ManifestError> {
    validate_target_name(&asset.target_name)?;
    validate_runtime(&asset.runtime)?;
    if asset.length == 0 || asset.length > MAX_ASSET_BYTES {
        return Err(ManifestError::Invalid(format!(
            "asset {:?} length must be between 1 and {MAX_ASSET_BYTES} bytes",
            asset.target_name
        )));
    }
    validate_url(&asset.download_origin, "download_origin")?;
    validate_provenance(&asset.provenance)?;
    match (
        &asset.operating_system,
        &asset.archive_format,
        &asset.runtime.libc,
    ) {
        (TargetOperatingSystem::Windows, ArchiveFormat::Zip, None)
        | (TargetOperatingSystem::Linux, ArchiveFormat::TarGz, Some(Libc::Glibc)) => {}
        _ => {
            return Err(ManifestError::Invalid(format!(
                "asset {:?} has contradictory operating_system, archive_format, or libc",
                asset.target_name
            )));
        }
    }
    Ok(())
}

fn validate_runtime(runtime: &RuntimeRequirements) -> Result<(), ManifestError> {
    validate_string(&runtime.minimum, "runtime.minimum", MAX_STRING_BYTES)?;
    match runtime.libc {
        Some(Libc::Glibc) if runtime.minimum.starts_with("glibc-") => Ok(()),
        Some(_) | None if runtime.minimum.starts_with("windows-") => Ok(()),
        _ => Err(ManifestError::Invalid(
            "runtime.minimum and libc are contradictory".into(),
        )),
    }
}

fn validate_release_notes(notes: &ReleaseNotes) -> Result<(), ManifestError> {
    validate_string(&notes.title, "release_notes.title", MAX_STRING_BYTES)?;
    validate_url(&notes.url, "release_notes.url")
}

fn validate_provenance(provenance: &AssetProvenance) -> Result<(), ManifestError> {
    validate_string(
        &provenance.source_repository,
        "provenance.source_repository",
        MAX_STRING_BYTES,
    )?;
    if provenance.source_repository != RELEASE_REPOSITORY {
        return Err(ManifestError::Invalid(
            "provenance.source_repository is not this repository".into(),
        ));
    }
    validate_string(
        &provenance.source_revision,
        "provenance.source_revision",
        40,
    )?;
    if provenance.source_revision.len() != 40
        || !provenance
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ManifestError::Invalid(
            "provenance.source_revision must be a full hexadecimal commit".into(),
        ));
    }
    validate_string(
        &provenance.build_workflow,
        "provenance.build_workflow",
        MAX_STRING_BYTES,
    )?;
    validate_string(
        &provenance.build_id,
        "provenance.build_id",
        MAX_STRING_BYTES,
    )
}

fn validate_compatibility(record: &CompatibilityRecord) -> Result<(), ManifestError> {
    let tuple = &record.tuple;
    for (value, field) in [
        (&tuple.hook_event, "hook_event"),
        (&tuple.hook_protocol, "hook_protocol"),
        (&tuple.required_tool, "required_tool"),
        (&tuple.tool_input_schema, "tool_input_schema"),
        (&tuple.response_behavior, "response_behavior"),
    ] {
        validate_string(value, field, MAX_STRING_BYTES)?;
    }
    if tuple.hook_event != "PermissionRequest"
        || tuple.hook_protocol != "permission-request-v1"
        || tuple.required_tool != "Bash"
        || tuple.tool_input_schema != "command-string-v1"
        || tuple.response_behavior != "one-request-structured-allow"
    {
        return Err(ManifestError::Invalid(
            "compatibility record has an unsupported hook/tool/response schema".into(),
        ));
    }
    match &record.eligibility {
        CompatibilityEligibility::Reviewed { evidence_ref } => {
            validate_string(evidence_ref, "evidence_ref", MAX_EVIDENCE_REF_BYTES)?;
        }
        CompatibilityEligibility::Experimental { .. } => {}
        CompatibilityEligibility::Excluded { reason } => {
            validate_string(reason, "exclusion reason", MAX_STRING_BYTES)?;
        }
    }
    Ok(())
}

fn compatibility_identity(tuple: &CompatibilityTuple) -> String {
    format!(
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
    )
}

fn validate_target_name(value: &str) -> Result<(), ManifestError> {
    validate_string(value, "target name", MAX_TARGET_NAME_BYTES)?;
    if value.starts_with('/')
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ManifestError::Invalid(
            "target names must be relative slash-separated paths without traversal".into(),
        ));
    }
    Ok(())
}

fn validate_url(value: &str, field: &str) -> Result<(), ManifestError> {
    validate_string(value, field, MAX_STRING_BYTES)?;
    if !value.starts_with(HTTPS_PREFIX)
        || value.contains(char::is_whitespace)
        || value.contains('#')
        || value.contains('?')
    {
        return Err(ManifestError::Invalid(format!(
            "{field} must be an https URL without query or fragment"
        )));
    }
    Ok(())
}

fn validate_string(value: &str, field: &str, maximum: usize) -> Result<(), ManifestError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(ManifestError::Invalid(format!(
            "{field} must be non-empty, at most {maximum} bytes, and free of control characters"
        )));
    }
    Ok(())
}

fn canonical_json(manifest: &ReleaseManifest) -> Result<Vec<u8>, ManifestError> {
    let mut normalized = manifest.clone();
    normalized
        .assets
        .sort_by(|left, right| left.target_name.cmp(&right.target_name));
    normalized
        .compatibility
        .sort_by_key(|record| compatibility_identity(&record.tuple));
    serde_json::to_vec(&normalized).map_err(ManifestError::Json)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("validated lowercase hexadecimal input"),
    }
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<(), ManifestError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer.deserialize_any(DuplicateKeyVisitor)?;
    deserializer.end()?;
    Ok(())
}

struct DuplicateKeySeed;

impl<'de> de::DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> de::Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = access.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            access.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        while access.next_element_seed(DuplicateKeySeed)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const VALID_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/distribution_manifest/valid.json"
    ));
    const DUPLICATE_KEY_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/distribution_manifest/duplicate-key.json"
    ));
    const UNKNOWN_FIELD_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/distribution_manifest/unknown-field.json"
    ));

    fn valid_json() -> String {
        VALID_FIXTURE.to_owned()
    }

    fn replace_once(input: &str, from: &str, to: &str) -> String {
        let (prefix, suffix) = input
            .split_once(from)
            .unwrap_or_else(|| panic!("fixture does not contain {from:?}"));
        format!("{prefix}{to}{suffix}")
    }

    #[test]
    fn synthetic_valid_manifest_is_typed_but_not_authenticated() {
        let parsed = parse_manifest(VALID_FIXTURE.as_bytes()).expect("valid fixture");
        assert_eq!(parsed.manifest().release_version.to_string(), "0.2.0");
        assert_eq!(parsed.manifest().assets.len(), 2);
        assert_eq!(parsed.manifest().compatibility.len(), 3);
        assert!(parsed.byte_length() > 0);
        assert!(!parsed.canonical_json().expect("canonical JSON").is_empty());
    }

    #[test]
    fn canonical_serialization_sorts_identity_arrays() {
        let mut value: Value = serde_json::from_str(VALID_FIXTURE).expect("fixture JSON");
        value["assets"] = Value::Array(
            value["assets"]
                .as_array()
                .expect("assets")
                .iter()
                .rev()
                .cloned()
                .collect(),
        );
        let reversed = serde_json::to_string(&value).expect("reversed fixture");
        let first = parse_manifest(VALID_FIXTURE.as_bytes())
            .expect("first manifest")
            .canonical_json()
            .expect("first canonical JSON");
        let second = parse_manifest(reversed.as_bytes())
            .expect("reversed manifest")
            .canonical_json()
            .expect("second canonical JSON");
        assert_eq!(first, second);
    }

    #[test]
    fn duplicate_keys_are_rejected_at_any_nesting_level() {
        assert!(matches!(
            parse_manifest(DUPLICATE_KEY_FIXTURE.as_bytes()),
            Err(ManifestError::Json(_))
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(matches!(
            parse_manifest(UNKNOWN_FIELD_FIXTURE.as_bytes()),
            Err(ManifestError::Json(_))
        ));
        let nested = replace_once(
            &valid_json(),
            "\"title\": \"Synthetic release fixture\"",
            "\"title\": \"Synthetic release fixture\", \"unexpected\": true",
        );
        assert!(matches!(
            parse_manifest(nested.as_bytes()),
            Err(ManifestError::Json(_))
        ));
    }

    #[test]
    fn bounded_input_and_unsupported_schema_are_rejected() {
        let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
        assert!(matches!(
            parse_manifest(&oversized),
            Err(ManifestError::TooLarge { .. })
        ));
        let unsupported = replace_once(
            &valid_json(),
            "\"schema_version\": 1",
            "\"schema_version\": 2",
        );
        assert!(matches!(
            parse_manifest(unsupported.as_bytes()),
            Err(ManifestError::UnsupportedSchemaVersion(2))
        ));
    }

    #[test]
    fn malformed_versions_hashes_lengths_and_runtime_are_rejected() {
        for (from, to) in [
            (
                "\"release_version\": \"0.2.0\"",
                "\"release_version\": \"0.2\"",
            ),
            (
                "\"release_version\": \"0.2.0\"",
                "\"release_version\": \"0.2.0-beta\"",
            ),
            (
                "\"sha256\": \"0000000000000000000000000000000000000000000000000000000000000000\"",
                "\"sha256\": \"not-a-sha256\"",
            ),
            ("\"length\": 12345", "\"length\": 0"),
            (
                "\"archive_format\": \"zip\"",
                "\"archive_format\": \"tar-gz\"",
            ),
            (
                "\"required_tool\": \"Bash\"",
                "\"required_tool\": \"PowerShell\"",
            ),
        ] {
            let invalid = replace_once(&valid_json(), from, to);
            assert!(
                parse_manifest(invalid.as_bytes()).is_err(),
                "invalid fixture {to}"
            );
        }
    }

    #[test]
    fn duplicate_assets_and_contradictory_compatibility_are_rejected() {
        let mut value: Value = serde_json::from_str(VALID_FIXTURE).expect("fixture JSON");
        let first_asset = value["assets"][0].clone();
        value["assets"]
            .as_array_mut()
            .expect("assets")
            .push(first_asset);
        let duplicate_asset = serde_json::to_vec(&value).expect("duplicate asset JSON");
        assert!(parse_manifest(&duplicate_asset).is_err());

        let mut value: Value = serde_json::from_str(VALID_FIXTURE).expect("fixture JSON");
        let first_record = value["compatibility"][0].clone();
        value["compatibility"]
            .as_array_mut()
            .expect("compatibility")
            .push(first_record);
        let duplicate_record = serde_json::to_vec(&value).expect("duplicate record JSON");
        assert!(parse_manifest(&duplicate_record).is_err());
    }

    #[test]
    fn tuf_authentication_requires_matching_verified_target() {
        let parsed = parse_manifest(VALID_FIXTURE.as_bytes()).expect("valid fixture");
        let asset = parsed.manifest().manifest_target.clone();
        let wrong_digest =
            Sha256Digest::parse("0000000000000000000000000000000000000000000000000000000000000000")
                .expect("test digest");
        let wrong = TufVerifiedTarget::from_verified_metadata(
            "metadata/releases/other.json".into(),
            VALID_FIXTURE.len() as u64,
            wrong_digest.clone(),
        );
        assert!(parsed.clone().authenticate_tuf(wrong).is_err());

        let wrong_hash = TufVerifiedTarget::from_verified_metadata(
            asset.clone(),
            VALID_FIXTURE.len() as u64,
            wrong_digest,
        );
        assert!(parsed.clone().authenticate_tuf(wrong_hash).is_err());

        let digest = Sha256Digest::from_bytes(VALID_FIXTURE.as_bytes());
        let correct =
            TufVerifiedTarget::from_verified_metadata(asset, VALID_FIXTURE.len() as u64, digest);
        let authenticated = parsed
            .authenticate_tuf(correct)
            .expect("matching TUF proof");
        assert_eq!(
            authenticated.manifest().release_version.to_string(),
            "0.2.0"
        );
        assert_eq!(
            authenticated.tuf_target().length,
            VALID_FIXTURE.len() as u64
        );
    }
}
