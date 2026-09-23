//! The embedded manifest is the only source of production approval authority.
//! Discovery, capability probes and historical records cannot add entries.
use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const MANIFEST_BYTES: &str = include_str!("../compatibility/manifest.json");

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub autoapprover_version: String,
    pub entries: Vec<Certificate>,
    pub revoked_artifact_sha256: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub evidence_id: String,
    pub target: Target,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub codex_version: String,
    pub os: String,
    pub arch: String,
    pub os_release: String,
    pub os_build: String,
    pub sandbox: String,
    pub surface: String,
    pub protocol: String,
    pub tool: String,
    pub codex_binary_sha256: String,
    pub codex_bundle_sha256: String,
    pub launch_kind: String,
    pub launch_artifact_sha256: String,
    pub launch_package_sha256: String,
}

impl Manifest {
    pub fn embedded() -> Result<Self> {
        Self::parse(MANIFEST_BYTES.as_bytes())
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // serde_json alone permits duplicate map keys. Use the same bounded,
        // recursive duplicate-key rejection as the hook parser.
        let value = crate::protocol::parse_unique_object(bytes)
            .map_err(|_| anyhow::anyhow!("invalid or duplicate compatibility manifest fields"))?;
        let manifest: Self =
            serde_json::from_value(value).context("decode compatibility manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 2 || self.autoapprover_version != env!("CARGO_PKG_VERSION") {
            bail!("unsupported manifest schema or autoapprover version")
        }
        let mut ids = HashSet::new();
        let mut targets = HashSet::new();
        for entry in &self.entries {
            entry.target.validate()?;
            if entry.evidence_id.is_empty()
                || !entry
                    .evidence_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || !ids.insert(&entry.evidence_id)
                || !targets.insert(&entry.target)
            {
                bail!("invalid or duplicate compatibility certificate")
            }
            if entry.target.artifact_digests().iter().any(|digest| {
                self.revoked_artifact_sha256
                    .iter()
                    .any(|item| item == *digest)
            }) {
                bail!("a revoked Codex artifact cannot be certified")
            }
        }
        let mut revoked = HashSet::new();
        for digest in &self.revoked_artifact_sha256 {
            if !is_sha256(digest) || !revoked.insert(digest) {
                bail!("invalid or duplicate artifact revocation")
            }
        }
        Ok(())
    }

    pub fn admits(&self, observed: &Target) -> bool {
        self.validate().is_ok()
            && observed.validate().is_ok()
            && !observed.artifact_digests().iter().any(|digest| {
                self.revoked_artifact_sha256
                    .iter()
                    .any(|item| item == *digest)
            })
            && self.entries.iter().any(|entry| &entry.target == observed)
    }
}

impl Target {
    fn artifact_digests(&self) -> [&str; 4] {
        [
            &self.codex_binary_sha256,
            &self.codex_bundle_sha256,
            &self.launch_artifact_sha256,
            &self.launch_package_sha256,
        ]
    }

    pub fn validate(&self) -> Result<()> {
        if crate::codex::parse_version(&format!("codex-cli {}", self.codex_version)).is_err()
            || !matches!(self.arch.as_str(), "x86_64" | "aarch64")
            || self.os_release.is_empty()
            || self.os_build.is_empty()
            || self.surface != "native-cli"
            || self.protocol != crate::arming::PROTOCOL_VERSION
            || self.tool != "Bash"
            || !is_sha256(&self.codex_binary_sha256)
            || !is_sha256(&self.codex_bundle_sha256)
            || !is_sha256(&self.launch_artifact_sha256)
            || !is_sha256(&self.launch_package_sha256)
            || !matches!(
                self.launch_kind.as_str(),
                "native" | "npm-bin" | "npm-cmd" | "npm-ps1"
            )
            || !matches!(
                (self.os.as_str(), self.launch_kind.as_str()),
                ("linux", "native" | "npm-bin") | ("windows", "native" | "npm-cmd" | "npm-ps1")
            )
        {
            bail!("incomplete or unsupported compatibility target")
        }
        if !matches!(
            (self.os.as_str(), self.sandbox.as_str()),
            ("linux", "linux-bwrap" | "linux-landlock")
                | ("windows", "windows-elevated" | "windows-unelevated")
        ) {
            bail!("sandbox does not match the target OS")
        }
        Ok(())
    }
}

pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn print_support_matrix() -> Result<i32> {
    let manifest = Manifest::embedded()?;
    println!("{}", serde_json::to_string(&manifest)?);
    Ok(0)
}

pub fn verify_manifest_file(path: &std::path::Path) -> Result<i32> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 || Manifest::parse(&bytes)? != Manifest::embedded()? {
        bail!("installer manifest does not equal this executable's embedded manifest")
    }
    println!(
        "Installer and executable compatibility manifests match; certification status is unchanged."
    );
    Ok(0)
}

#[cfg(test)]
pub fn fixture_target() -> Target {
    Target {
        codex_version: "0.156.0".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        os_release: "synthetic-fixture".into(),
        os_build: "synthetic-build".into(),
        sandbox: "linux-bwrap".into(),
        surface: "native-cli".into(),
        protocol: crate::arming::PROTOCOL_VERSION.into(),
        tool: "Bash".into(),
        codex_binary_sha256: "a".repeat(64),
        codex_bundle_sha256: "b".repeat(64),
        launch_kind: "npm-bin".into(),
        launch_artifact_sha256: "c".repeat(64),
        launch_package_sha256: "d".repeat(64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_requires_equality_of_every_dimension() {
        let target = fixture_target();
        let mut manifest = Manifest::embedded().unwrap();
        manifest.entries = vec![Certificate {
            evidence_id: "synthetic-test-only".into(),
            target: target.clone(),
        }];
        assert!(manifest.admits(&target));
        let value = serde_json::to_value(&target).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut changed = value.clone();
            changed[field] = serde_json::json!("different");
            let changed: Target = serde_json::from_value(changed).unwrap();
            assert!(!manifest.admits(&changed), "admitted changed {field}");
        }
        for digest in target.artifact_digests() {
            manifest.revoked_artifact_sha256 = vec![digest.to_owned()];
            assert!(!manifest.admits(&target));
        }
    }

    #[test]
    fn historical_and_synthetic_records_are_not_shipped_as_certifications() {
        let manifest = Manifest::embedded().unwrap();
        assert!(!manifest.admits(&fixture_target()));
        assert!(
            !manifest
                .entries
                .iter()
                .any(|entry| entry.target.codex_version == "0.151.0")
        );
    }

    #[test]
    fn duplicate_keys_unknown_fields_and_incomplete_tuples_are_rejected() {
        for text in [
            r#"{"schema_version":2,"schema_version":2,"autoapprover_version":"0.1.0","entries":[],"revoked_artifact_sha256":[]}"#,
            r#"{"schema_version":2,"autoapprover_version":"0.1.0","entries":[],"revoked_artifact_sha256":[],"bypass":true}"#,
            r#"{"schema_version":2,"autoapprover_version":"0.1.0","entries":[{"evidence_id":"x","target":{"codex_version":"0.151.0","os":"linux"}}],"revoked_artifact_sha256":[]}"#,
        ] {
            assert!(Manifest::parse(text.as_bytes()).is_err());
        }
    }
}
