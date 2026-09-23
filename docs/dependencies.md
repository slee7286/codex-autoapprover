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
or establish that dependencies have no known vulnerabilities. Independent
review, target-specific SBOMs and a signed release artifact remain required.
The CI job retains this inventory as a review artifact, not as a production
attestation.

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
```

Use `--offline` to require already cached exact crate archives. An existing
output file is accepted only when its bytes match the regenerated document.
