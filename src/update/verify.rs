//! Narrow boundary between parsed metadata and publisher-authenticated metadata.
//!
//! The production authenticated-manifest type has no constructor in this
//! milestone. A future TUF verifier in this module must create it only after
//! root-chain, role, expiry, target-length, and target-hash verification.
//! The only constructor currently compiled is explicitly test-only and proves
//! byte binding for synthetic fixtures; it does not perform or claim TUF
//! publisher authentication.

#[cfg(test)]
use super::manifest::ParsedManifest;
use super::manifest::{ReleaseManifest, Sha256Digest};

/// A manifest whose exact bytes and target binding were established by the
/// verifier module. There is intentionally no production constructor, public
/// deserialization, or `Clone` implementation.
pub(crate) struct AuthenticatedManifest {
    manifest: ReleaseManifest,
    target: VerifiedTarget,
}

impl AuthenticatedManifest {
    pub(crate) fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    #[cfg(test)]
    fn target(&self) -> &VerifiedTarget {
        &self.target
    }
}

struct VerifiedTarget {
    target_name: String,
    length: u64,
    sha256: Sha256Digest,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VerificationError {
    Name,
    Length,
    Hash,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SyntheticTarget {
    target_name: String,
    length: u64,
    sha256: Sha256Digest,
}

#[cfg(test)]
impl SyntheticTarget {
    /// Test-only input for exercising the byte-binding seam.
    ///
    /// This accepts caller-supplied metadata deliberately so tests can prove
    /// that matching bytes are not the same thing as TUF publisher trust.
    pub(crate) fn from_untrusted_metadata(
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

#[cfg(test)]
pub(crate) fn synthetic_for_tests(
    parsed: ParsedManifest,
    target: SyntheticTarget,
) -> Result<AuthenticatedManifest, VerificationError> {
    let expected_name = parsed.manifest().manifest_target.clone();
    if target.target_name != expected_name {
        return Err(VerificationError::Name);
    }
    if target.length != parsed.byte_length() as u64 {
        return Err(VerificationError::Length);
    }
    if target.sha256 != *parsed.raw_sha256() {
        return Err(VerificationError::Hash);
    }

    Ok(AuthenticatedManifest {
        manifest: parsed.into_manifest(),
        target: VerifiedTarget {
            target_name: target.target_name,
            length: target.length,
            sha256: target.sha256,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::manifest::{Sha256Digest, parse_manifest};

    const VALID_FIXTURE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/distribution_manifest/valid.json"
    ));

    fn parsed_fixture() -> ParsedManifest {
        parse_manifest(VALID_FIXTURE.as_bytes()).expect("synthetic manifest is valid")
    }

    fn target_for(parsed: &ParsedManifest) -> SyntheticTarget {
        SyntheticTarget::from_untrusted_metadata(
            parsed.manifest().manifest_target.clone(),
            parsed.byte_length() as u64,
            Sha256Digest::from_bytes(VALID_FIXTURE.as_bytes()),
        )
    }

    #[test]
    fn synthetic_boundary_requires_exact_name_length_and_hash() {
        let parsed = parsed_fixture();
        let wrong_name = SyntheticTarget::from_untrusted_metadata(
            "metadata/releases/attacker.json".into(),
            parsed.byte_length() as u64,
            Sha256Digest::from_bytes(VALID_FIXTURE.as_bytes()),
        );
        assert!(matches!(
            synthetic_for_tests(parsed.clone(), wrong_name),
            Err(VerificationError::Name)
        ));

        let wrong_hash = SyntheticTarget::from_untrusted_metadata(
            parsed.manifest().manifest_target.clone(),
            parsed.byte_length() as u64,
            Sha256Digest::parse("0000000000000000000000000000000000000000000000000000000000000000")
                .expect("synthetic digest"),
        );
        assert!(matches!(
            synthetic_for_tests(parsed.clone(), wrong_hash),
            Err(VerificationError::Hash)
        ));

        let wrong_length = SyntheticTarget::from_untrusted_metadata(
            parsed.manifest().manifest_target.clone(),
            parsed.byte_length() as u64 + 1,
            Sha256Digest::from_bytes(VALID_FIXTURE.as_bytes()),
        );
        assert!(matches!(
            synthetic_for_tests(parsed, wrong_length),
            Err(VerificationError::Length)
        ));
    }

    #[test]
    fn matching_attacker_metadata_is_only_a_synthetic_test_boundary() {
        let parsed = parsed_fixture();
        let target = target_for(&parsed);
        let authenticated = synthetic_for_tests(parsed, target).expect("synthetic boundary");
        assert_eq!(
            authenticated.manifest().release_version.to_string(),
            "0.2.0"
        );
        assert_eq!(
            authenticated.target().target_name,
            "metadata/releases/0.2.0.json"
        );
        // This test exercises byte binding only. It does not execute TUF and
        // therefore supplies no publisher-authentication evidence.
    }

    #[test]
    fn authenticated_content_is_read_only_and_not_cloneable_as_a_wrapper() {
        let parsed = parsed_fixture();
        let target = target_for(&parsed);
        let authenticated = synthetic_for_tests(parsed, target).expect("synthetic boundary");
        let mut modified_copy = authenticated.manifest().clone();
        modified_copy.release_version =
            crate::update::manifest::StableVersion::parse("9.9.9").expect("stable version");
        assert_eq!(
            authenticated.manifest().release_version.to_string(),
            "0.2.0"
        );
        assert_eq!(modified_copy.release_version.to_string(), "9.9.9");
    }
}
