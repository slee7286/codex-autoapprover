# Locked dependency inventory

The local `Cargo.lock` contains 89 packages: codex-autoapprover and 88 registry
crates. `scripts/locked_sbom.py` generates a deterministic SPDX 2.3 JSON
inventory with each locked version, crate SHA-256, declared license, package
URL and dependency edge. The generator reads license metadata only from a
`.crate` archive whose SHA-256 matches `Cargo.lock`; missing archives are
fetched without redirects from `static.crates.io` and checked before use.

On 2026-09-23, seven target-specific crate archives were absent from the local
Cargo cache. Exact archives were downloaded to temporary storage and each
checksum matched the lock file. Every registry package had a declared license;
two legacy `MIT/Apache-2.0` style strings were normalized to SPDX `OR`
expressions, with the original text retained in the package comment. The
generated document passed the [official SPDX 2.3 JSON schema](https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json)
(SHA-256 `239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b`).

This is the complete **locked graph**, including optional, build, development
and target-specific packages. It does not identify which components are in a
particular Linux or Windows binary, conclude license compliance, ship notices,
or establish that dependencies have no known vulnerabilities. The CI job
retains it as review material, not a production attestation.

On 2026-09-23, a local `cargo-audit 0.22.2` scan compared all 89 locked
packages with 1,264 advisories from public [RustSec advisory-db](https://github.com/RustSec/advisory-db)
commit `f7dc4b2860b29978f400fda0aab31cc4dbd21134`. It reported zero
vulnerabilities and zero informational warnings. The database was cloned
without sending this repository's dependency names; the audit then ran with
`--no-fetch --no-yanked` against the local `Cargo.lock`. Its JSON report is
retained only at `/tmp/autoapprover-rustsec-audit-20260923.json` (SHA-256
`11c18bf84c806cea56e975d8f0befed13a2b10fb51a48f085c9bded88699caf1`).
This is a point-in-time [RustSec `cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit)
result, not a check for yanked crates, advisories absent from RustSec, exact
linked-code reachability, or an independent vulnerability review. The earlier
proposed OSV batch query was not sent because it would disclose the exact
lockfile inventory to a public API.

`scripts/binary_sbom.py` additionally selects the normal and build dependency
closure from Cargo's native target-filtered resolved graph. Its SPDX 2.3 file
names one candidate executable and binds its exact SHA-256 and source digest.
It checks the embedded support manifest and the selected crate archives
against `Cargo.lock`. A local Linux x86_64 release-build rehearsal selected 58
packages and passed the same official SPDX JSON schema. Dev-only and Windows
crates were excluded. The prepared native candidate workflow generates one
such document per Linux/Windows build, checks its bytes again after download,
and requests a binary-subject SBOM attestation. That workflow has not run.
This records build inputs, including proc macros; it does not prove exact
linked-code composition, enumerate compiler/standard-library/OS components,
or establish license and vulnerability clearance. Final consumer artifacts and
independent review remain necessary.

`scripts/locked_licenses.py` additionally creates a deterministic local archive
of top-level license and notice files from the same checksum-verified crate
archives. Its `inventory.json` records each file's SHA-256, the declared
license, the locked crate checksum and the current source digest. The script
uses only locally cached archives and fails if one is missing. The 2026-09-23
rehearsal found top-level license/notice files for 86 of 88 registry crates;
`difflib 0.4.0` and `r-efi 6.0.0` declared licenses but had no matching
top-level text in their published archives. Those cases need manual review.
The bundle covers the full lockfile, including crates that may not be linked
into a particular consumer binary. It is neither a final notice selection nor
a legal conclusion.

```sh
python scripts/locked_licenses.py --output /tmp/codex-autoapprover-locked-licenses.tar.gz
```

Generate a new inventory with Python 3.11 or later:

```sh
python scripts/locked_sbom.py --output /tmp/codex-autoapprover-locked-dependencies.spdx.json
cargo build --release --locked --bin codex-autoapprover
python scripts/binary_sbom.py --offline --binary target/release/codex-autoapprover --output /tmp/codex-autoapprover-linux-x86_64.spdx.json
```

Use `--offline` to require already cached exact crate archives. An existing
output file is accepted only when its bytes match the regenerated document.
