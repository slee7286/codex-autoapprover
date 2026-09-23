# Exact compatibility hardening — 2026-09-23

This is an implementation checkpoint after foundation commit `2c54080`, not a
production qualification. The complete objective remains
[production-goal.md](production-goal.md), including all eight workstreams and
all named native/install/release gates. No part of that objective is waived by
this checkpoint. Previous foundation checks were progress; this continuation
made additional code, gate, test and documentation changes.

## Current authoritative state

- The embedded schema-2 `compatibility/manifest.json` has **zero certified
  targets**. Historical Linux 0.151.0 no longer grants production authority.
- Runtime admission compares version, OS, architecture, exact OS release and
  build, explicitly selected sandbox, foreground CLI surface, protocol, tool
  and exact native executable, bundle, launcher and launch-package SHA-256.
  Artifact revocation covers all four digests. Legacy automatic settings
  cannot bypass it.
- Recognized npm launchers resolve to the native bundled executable; the
  launcher is not interpreted in an armed session. The complete native bundle
  is hashed and retained for per-decision identity checks. Unix files and
  directory chains writable by other users or groups are ineligible. The
  present local npm installation fails this restriction and stays unarmed.
  Windows file handles deny write/delete sharing. A conservative local-drive
  directory owner/DACL and reparse-point check is implemented and cross-compiled;
  it has not run natively or received independent review. Unknown ACE forms
  fail closed. No Windows tuple is certified.
- Linux launches the held executable inode through `/proc/self/fd`; Windows
  holds a file handle without write/delete sharing. The brokers recheck the
  configured path, file identity and actual running process image.
- Native observation rejects known SSH/remote, IDE, WSL, container and isolated
  namespace environments, including runners whose filesystem root UID is
  remapped away from host root. Missing host facts remain inconclusive. These checks
  are conservative detection, not hardware attestation or same-user isolation.
- Foreground admission restricts forwarded options and explicitly pins the
  selected sandbox while preserving the active permission profile. A bounded disposable
  shell/file health probe is implemented. It has not yet qualified a real
  Codex tuple; configuration/managed-policy coercion remains unresolved qualification work.
  Health probes resolve the same project cwd and only write a disposable child
  directory; a read-only profile that rejects the write stays manual.
- Brokers bind the first accepted session, consume a hook process invocation
  once, reject identical request replays, cap the ledger at 4096 invocations,
  and permit **at most one allow** in the isolated verifier. Consumed requests
  stay consumed if response delivery fails. Identical legitimate retries use
  normal approval. Both brokers now count connections before parsing and audit
  each parsed request before deciding; a malformed broker frame, denied request
  or replay invalidates the verifier's one-request check.
  Audit event names are reduced to fixed labels before logging, so malformed
  hook input cannot inject additional audit lines.
  A malformed hook input that never reaches the broker is outside this count.
  Same-user malicious descendants remain an open review item.
- A bounded, read-only `codex exec --json` trace inspector requires exactly one
  started and successfully completed exact command in a single turn. It rejects
  extra command and tool items, errors, duplicate JSON keys and truncated logs,
  and emits a redacted, explicitly non-certifying digest report. Its format
  follows the [official JSONL event documentation](https://learn.chatgpt.com/docs/non-interactive-mode)
  and the inspected upstream 0.156.0 event source. It has synthetic tests only;
  no unattended native hook run or independently witnessed outcome exists yet.
- Inspection of the [Codex 0.156.0 headless exec source](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/exec/src/lib.rs)
  found that it forces approvals to `never` unless auto-review is selected.
  A proposed `codex exec` verifier was withdrawn because ordinary headless mode
  cannot produce the required `PermissionRequest`, while enabling auto-review
  would expand authority beyond this exact-command verification. The existing
  interactive verifier remains non-promoting. A different bounded live harness
  and native validation are still required.
- Probe output uses private temporary files rather than unbounded thread joins
  on inherited pipes. Unix probe process groups are terminated on completion or
  timeout. The isolated interactive verifier now requests no shared daemon and
  bounds and stops its child on timeout or interruption. On Unix it now starts
  the verification child in a separate process group and kills its descendants
  before evidence inspection or cleanup, including when the parent exits first.
  This has synthetic regression coverage; native Codex testing is still needed.
  Windows probes and the verifier now launch suspended into kill-on-close Job
  Objects and stop those jobs before inspecting or removing verification state.
  A native Windows test is prepared to check a descendant after its parent
  exits, but it has only cross-compiled. Native execution and review remain
  required, including nested-job and shim cases.
- A process-boundary review found that the Windows named-pipe accept loop
  joined active workers after dropping completed-worker handles. One stalled
  client could therefore hold up a separate request until its two-second
  deadline. Worker reaping now retains active handles without joining them;
  the cross-platform bounded regression passes and a native Windows two-client
  test is prepared. The actual Windows pipe behavior remains unexecuted.
- Linux broker frame reads previously used one socket timeout for an entire
  `read_exact` call. A client sending partial bytes faster than that timeout
  could stretch the two-second request deadline. Each partial read and write
  now recomputes the remaining absolute deadline; a slow-sender Unix-socket
  regression passes. This bounds broker workers locally, not a live Codex run.
- The interactive verifier now serves a nonce-bound loopback endpoint and
  requires the exact one-request `curl` HEAD probe to reach it, alongside the
  broker request and allow counts. A local real-`curl` test and a wrong-path
  rejection test pass; neither invokes Codex. The verifier no longer passes
  `--dangerously-bypass-hook-trust`, because that flag can run other configured
  hooks under Codex's composition rules. The temporary hook now needs normal
  trust review. The verifier still shares the user's Codex configuration and
  authentication context and does not produce a reviewed native report; an
  isolated native qualification harness remains open.
- The schema-2 release gate compares the entire compiled manifest and evidence
  targets, includes the manifest in source hashing, requires consumer/upstream
  digests, retained artifact hashes, independent review identities and all
  named checks. It requires the retained consumer SPDX file to identify the
  reviewed binary digest, native target and current source. It now also
  requires a retained, clean-tree build record whose commit matches the
  native report and whose source, binary, lockfile, manifest, native target,
  toolchain and host fields pass bounded checks. This remains structural
  validation, not independent proof of build provenance. Source files
  sort by canonical relative UTF-8 path so Linux and Windows runners compute
  the same source digest. Reports expire for release qualification after 30 days.
- Windows bundle directory admission now reads owner and DACL information from
  no-reparse directory handles. It rejects null DACLs, untrusted ownership,
  unknown ACE forms and untrusted write, delete, owner or DACL rights; each
  bundle subdirectory is checked as a leaf. A native regression test is
  prepared to reject a disposable directory after granting BUILTIN\\Users
  Modify rights. This remains unexecuted on Windows, and handle/ACL races and
  normal Windows installation ACLs require independent review. The check uses
  [Microsoft's file security model](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
  and [handle-based security descriptor API](https://learn.microsoft.com/en-us/windows/win32/api/Aclapi/nf-aclapi-getsecurityinfo).
- The prepared watcher now checks out the candidate branch separately for
  Rust tests while running metadata and probe scripts from the trusted
  default-branch checkout. Initial and post-repair checks require the branch's
  recorded candidate metadata to equal a freshly fetched official record
  before downloading either native asset. On an update the watcher also
  rechecks the previously recorded release assets, all seven npm package
  identities, and the Git tag object and source commit before preparing a
  new candidate. The checked-in unverified schema-3 0.156.0 record now pins
  those identities from the official 2026-09-23 snapshot;
  it does not establish any earlier digest history or native qualification.
  Asset/CLI preflight is now a separate
  job; its failures cannot reach the repair worker. The official record now
  includes exact SHA-512 registry integrity for the npm parent and six native
  aliases. Candidate runners compare a script-free exact-version npm lock
  against all seven records, install with `npm ci`, audit registry signatures
  and attestations, and probe that installation. Only a disposable Linux
  rehearsal has run; Windows and the workflow itself remain untested. The
  repair job also requires a short signal artifact created after a Rust check
  command fails. Checkout and toolchain setup failures cannot produce it.
  Cargo failures caused by a runner problem can still spend one bounded
  attempt; no live workflow run has confirmed the classification. The
  watcher now marks only a newly opened candidate PR eligible for automatic
  repair. A bounded scan back to the checked-in baseline queues every newer
  stable version oldest first; each poll selects one with no earlier
  same-repository PR, including closed decisions. Exact by-tag refresh keeps
  candidate and post-repair runners pinned to that selected version even when
  newer releases exist. Open same-repository PR files are fetched at the PR's
  exact head commit and checked against current official asset, npm and Git
  tag identities; drift or a branch race stops catch-up. The repair worker
  checks its checkout against the pinned tag object and commit before using
  upstream source as untrusted context. An explicit dispatch can
  retry an exact version.
  Unchanged releases skip candidate jobs and do not require a deleted
  post-merge branch. The
  watcher resolves a single candidate commit and pins preflight, Rust checks
  and repair to it; post-repair checks pin the pushed repair commit. This has
  local fixtures, a read-only live metadata rehearsal and workflow structure
  checks only; no default-branch run or native approval validation.
- The Windows source installer verifies that its source manifest equals the
  installed executable's embedded manifest before configuration changes.
  The explicit TOML edit now rejects hardlinked or reparse-point config files,
  symlinked or junction directory chains, and input over 4 MiB. Linux tests
  exercise the link and size refusals; Windows hardlink and junction cases are
  prepared for PowerShell 5.1/7 CI but have not run natively. Configuration
  repair now reuses the owner/DACL check on its directory and existing file;
  broad-write directory and file regressions are prepared but unrun. Directory
  ACL preservation and crash recovery still require Windows review.
- A Linux prebuilt-artifact installer now checks an expected SHA-256, embedded
  manifest equality and executable health before selecting a release. It uses
  private directories, digest-addressed releases, a lock and atomic symlink
  updates. Install, rollback and uninstall journals finish interrupted pointer
  changes on the next invocation; recovery refuses malformed/conflicting
  journals and unmanaged pointer files. Power-loss durability and disk-full
  behavior still need separate testing.
  It has no authenticated public artifact to install yet.
- A deterministic Linux development archive includes the exact installer,
  binary, manifest, licence, README and per-file digest metadata. Two local
  builds compared byte-for-byte, and the extracted executable installed and
  uninstalled from a disposable directory. Its checksum is unsigned and its
  metadata explicitly says unqualified.
- A separate Windows artifact installer now stages a supplied native executable
  against an externally authenticated SHA-256 and the source manifest, keeps
  digest-addressed releases under `LOCALAPPDATA`, and journals same-volume
  replacement, rollback and uninstall. It refuses unmanaged files, directory
  reparse points and broad-write ACLs. A deterministic, explicitly unqualified
  Windows development ZIP and exact-byte extracted install, reinstall, upgrade,
  rollback and uninstall rehearsal are prepared. The PowerShell files passed a
  Linux-host syntax parse, and ZIP serialization has local Python coverage;
  **none of this has run on native Windows**. Native ACL behavior, locked-file
  replacement and recovery must be
  verified and corrected before this path can support a consumer release.
- The preliminary SPDX 2.3 locked-dependency inventory lists 89 exact packages
  and 137 relationships. All 88 third-party archive checksums matched
  `Cargo.lock`; declared licenses were read from those archives. It passed the
  official SPDX 2.3 JSON schema locally, but no independent license or
  vulnerability conclusion has been made.
- A native Linux x86_64 binary build-input SPDX 2.3 rehearsal selects 58
  normal/build packages from Cargo's target-filtered graph, excluding dev-only
  and Windows packages. The document binds the exact local executable and
  source digests, passes the official SPDX schema, and rejects a changed binary
  when compared with the staged document. The candidate workflow prepares the
  same path for native Windows and binary-subject SBOM attestations, but has not
  run. A separate bounded native build observation now records a clean Git
  revision, toolchain versions, selected host facts and matching source/binary
  digests; its workflow path has been rehearsed locally on Linux only. It is
  self-reported, not reproducibility proof or a linked compiler/OS inventory.
  Exact linked-code composition and independent dependency review are missing.
- An offline, deterministic license-text bundle now indexes top-level license
  and notice files from the same 88 checksum-verified crate archives and the
  project's own MIT license. `difflib 0.4.0` and `r-efi 6.0.0` lack matching
  top-level text in their published archives and remain manual review items.
  The bundle is preliminary, covers the full lockfile and is not a final
  consumer notice set or independent legal review.
- An offline `cargo-audit 0.22.2` scan of the complete 89-package lockfile
  against pinned public RustSec advisory-db commit
  `f7dc4b2860b29978f400fda0aab31cc4dbd21134` reported zero vulnerabilities
  and zero informational warnings. The database contains 1,264 advisories;
  yanked status was not queried. This point-in-time RustSec result does not
  establish a complete vulnerability review or exact binary reachability.
- A manual main-branch workflow now prepares native Linux and Windows
  candidate binaries and checksums. Separate jobs gate the exact downloaded
  bytes; a protected-environment job can attest candidate build provenance
  without implying approval compatibility. It checks environment review and
  branch rules before requesting attestations. The workflow has not run, and
  its PowerShell staging and native release gates remain untested on Windows.

## Verification performed

| Check | Result and scope |
| --- | --- |
| `cargo test --locked --all-targets` | 79 unit tests and 22 integration tests passed on Linux with host Unix-socket and loopback access; synthetic regression evidence only. New cases cover linked/oversized configuration refusal, malformed/denied/replayed broker audit accounting, log-injection rejection, Unix descendant cleanup, nonblocking worker reaping, whole-frame slow-sender deadlines, the exact loopback witness and redacted diagnostic retention after temporary-state cleanup. |
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo clippy --locked --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings` | Passed with the prepared directory ACL, suspended Job Object child-tree module, and native-only descendant and stalled-pipe regressions; compile/lint only, no Windows execution |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 89 tests passed. Reproducibility archive tests reject traversal, links, case collisions and a linked expected binary; a release-gate case changes each reproducibility binding while updating its retained hash and confirms the gate still rejects it. Synthetic fixtures are not production evidence. |
| `cargo build --release --locked --bin codex-autoapprover` | Local development executable built |
| `release_gate.py --binary ...` | Exact compiled/source manifest equality passes; production remains blocked |
| `release_gate.py --require-ready --binary ...` | Correctly rejects incomplete qualification |
| `verify-manifest --manifest compatibility/manifest.json` | Installed/source manifest comparison passes for the local binary |
| `scripts/test-install-linux.sh target/release/codex-autoapprover` | Disposable Linux install, identical reinstall with renewed manifest/health checks, mismatched-manifest rejection without replacing the current release, synthetic changed-artifact upgrade, rollback, tamper/unmanaged-path rejection, uninstall, journal recovery at each install-pointer boundary and interrupted first install passed. A file-size-limited upgrade failed during its staged copy; the prior executable remained selected and the next status call cleared partial stages. This is not a physical disk-full or power-loss test. Malformed/conflicting journals were rejected and Codex home content stayed unchanged. |
| `scripts/test-package-linux.sh target/release/codex-autoapprover` | Two builds of one development archive were byte-identical; a byte-distinct second archive passed checksum and per-file checks; exact extracted bytes were installed, reinstalled, upgraded, rolled back and uninstalled in a disposable directory. The native filesystem-owner check required host access because the restricted sandbox remapped `/` to UID 65534. These unsigned archives are not consumer release artifacts. |
| Linux-host PowerShell 7.6.6 parser | Parsed the new Windows installer and two native test scripts without syntax errors. This did not execute the installer or exercise Windows PowerShell 5.1. |
| Prepared Windows candidate workflow | YAML parsed; the changed Windows build and qualification steps passed a Linux-host PowerShell 7.6.6 syntax parse. Lifecycle tests remain configured for Windows PowerShell 5.1 and 7 and extracted ZIP rehearsal for PowerShell 7; no native workflow run occurred. |
| `scripts/build_record.py` and Linux candidate staging/qualification scripts | From clean commit `75fb721`, staged the exact Linux binary, SPDX file and build observation with three verified SHA-256 entries. The gate's new build-record validator accepted the exact local record structure. A separate clean checkout rechecked all three files, regenerated the SBOM identically, then correctly failed the still-pending production gate. This was a local rehearsal, not a GitHub provenance run or native approval test. |
| `python3 scripts/locked_sbom.py --offline --output /tmp/...` | Generated 89-package, 137-relationship SPDX 2.3 locked inventory from checksum-verified crate archives; local official-schema validation passed |
| `python3 scripts/binary_sbom.py --offline --binary ... --output /tmp/...` | Generated a 58-package Linux x86_64 native binary build-input SPDX 2.3 document, rechecked staged bytes and document idempotently, rejected a modified executable, and passed the locally retained official SPDX schema; no Windows execution or signed attestation |
| `python3 scripts/locked_licenses.py --output /tmp/...` | Reproduced a deterministic 171-file local bundle with an exact inventory; top-level license/notice text was absent for two of 88 registry crates. This is review material, not a legal conclusion. |
| Local `cargo-audit 0.22.2 audit --no-fetch --no-yanked --format json` | Scanned all 89 locked packages against 1,264 advisories at pinned RustSec database commit `f7dc4b2860b29978f400fda0aab31cc4dbd21134`; reported zero vulnerabilities and zero warnings. The JSON report remains in `/tmp`, and no lockfile inventory was sent in the audit request. |
| Disposable npm Codex 0.156.1 candidate | Fetched seven official registry package identities; exact-version lock and installed Linux parent/native package matched the recorded SHA-512 integrities. Script-free `npm ci` and `npm audit signatures` passed; npm reported two verified registry signatures and attestations. Version/help/features probes passed against the installed shim. This is non-live Linux-only evidence, not approval qualification. |
| Pinned repair-tool npm install | Lock SHA-256 `c60fdc7dd9c125db519fd38ce82d702aa8a177930ee9291d06c65b2530780464` matched fresh 0.156.0 registry metadata; script-free `npm ci` installed the parent and Linux native package, installed-layout verification passed, npm reported two verified signatures and attestations, and the CLI reported `codex-cli 0.156.0`. The 89 Python fixtures and YAML parse passed. This is a local pre-key supply-chain rehearsal, not a default-branch repair run or approval qualification. |
| Candidate provenance and watcher workflow static review | YAML structure, main-only provenance dispatch, token permissions, job order, Bash and inline Python syntax passed locally. The watcher repair-signal guard rejected missing/invalid fixtures and accepted an exact fixture; no GitHub run, environment approval, provenance signature or Windows PowerShell execution occurred |
| Native repeat-build preparation | Two separate offline Rust 1.98.0 Linux release builds of clean commit `8187e42` matched byte-for-byte at SHA-256 `3f0162c34e5f95a0effaf2d14ff5fa2764499bcf9d60439b6225f2609d64b178`. The integrated script then built clean commits `fbe6def` and `f39de8b` twice each and matched the same executable digest to the local candidate; the `f39de8b` report is `/tmp/autoapprover-repro-f39de8b.json`, SHA-256 `7e0f1ce28c15a823c8e662f8fab5372503af2756fd6ca396851727cab5f1266d`. The verifier accepted it, also accepted the prior report from a separate directory, and rejected a changed binary-digest field. A Linux-host PowerShell 7.6.6 parser accepted the changed Windows workflow blocks. This is local same-host repeatability, not a native Windows run, signed provenance, or an independent reproduction. |
| Read-only GitHub CLI PR field check | The candidate `gh pr list --head ... --state all --json ...` query was accepted and returned no existing 0.156.0 candidate PR. A separate existing public PR showed the expected owner, same-repository flag, `OPEN` state and 40-character head commit fields. This verified JSON shape only; no PR was created or changed. |
| Read-only live source-pin rehearsal | Official 0.156.0 release metadata still matched the checked-in schema-3 record, including annotated tag object `476ac1aae33835e6e4c2d311c254b9b6ce9b2f4c` and commit `fe74a774532af67b5a4a3dec03ce9469e17f89af`; temporary exact-version output matched it byte-for-byte as JSON. A separate temporary bounded poll selected unverified 0.156.1, release id `394258789`, tag object `81e8e29b2956dfe9b092c63953a9ed282781e77c` and commit `b412ff32c417f855c2b2d1581b77058eed87c84b`; a repeat poll reported unchanged. This did not create a PR, run native validation or qualify support. |
| Disposable `verify-local-hook` attempt | No live Codex child started: host-access PTY was classified `isolated-namespace`; default PTY could not create the private broker socket. Both copied-auth temporary homes were removed. A later host-access `script(1)` pseudo-terminal diagnosis was also `isolated-namespace`. No PermissionRequest, allow or command outcome exists. |
| `git diff --check` | Passed |

The first sandboxed test run could not create private Unix sockets. Running the
same suite with host socket access passed. New regression coverage includes
every tuple-field mismatch, revocation, duplicate manifest fields, historical
version spoofing, native-image replacement, symlink retargeting/hardlinks,
hung probes/descendant-held output, session rebinding/replay and concurrent
single-allow consumption. These results do not prove native Codex behavior.

Local development artifact: `target/release/codex-autoapprover`, SHA-256
`4d80a46ee8c52574d442016944c5acb8781b2b5b70c46293298cdce1bbfea65e`.
This is neither a signed consumer package nor a qualified production binary.
Rebuilds after further source edits require recording a new digest.

Latest local development archive:
`/tmp/autoapprover-dev-package-20260923-v40/codex-autoapprover-0.1.0-linux-x86_64-dev.tar.gz`,
SHA-256 `bac26dc93990dae2c42c563b334f550647fca2fe8c430907446ddcd0aef06591`.
Its recorded source digest is
`32759b558be27cc08419fcec07aefd5020930f71d5c22168051f84ce0248bca2`.
It is unsigned, unqualified and stored only in temporary local storage.

The matching preliminary locked-dependency inventory is
`/tmp/autoapprover-locked-dependencies-v38.spdx.json`, SHA-256
`bf895c0c4b90476bf27bedf9efbdfcd9dc4c484e1722b4198da29bc0b7e9e159`.
It passed the locally retained official SPDX 2.3 schema. It is not an
attestation, a binary-specific SBOM or an independent dependency review.

The local Linux binary build-input document is
`/tmp/autoapprover-binary-linux-v16.spdx.json`, SHA-256
`a1e7ff6eb10e286f3e6a11c5b57da611aee4d592d908295dfb0c131bbc97ec2a`.
It records 58 packages and 84 relationships, passed the same SPDX schema,
and binds the development executable digest above. Both SPDX files used
`SOURCE_DATE_EPOCH=1790143138` for reproducible local output. This is neither
a signed SBOM attestation nor a conclusion about exact linked components.

The separate preliminary license-material bundle is
`/tmp/autoapprover-locked-licenses-v20.tar.gz`, SHA-256
`84e4817158332de2137155bff2e8f0d5ba46f07aac967caaa4dd8b0ec0e3548a`.
Its indexed source digest matches the archive above.

The Linux candidate build observation is
`/tmp/autoapprover-candidate-record-v6/candidate-linux/build-record.json`,
SHA-256 `1a36f2a10ba360f3af850a6e07dd9be60aff3eb7e10acdcb472b030c8ceff013`.
It records clean commit `9dd645d7cca1657187e53ce5cb4e9149f54977b2`,
the same source and binary digests as the archive, Rust/Cargo 1.98.0 and
the local Ubuntu 26.04 host. It is a self-reported local observation, not
verified build provenance or native Codex evidence.

An automatic approval review rejected a proposed live OSV batch query because
it would transmit the potentially sensitive exact `Cargo.lock` inventory to a public API. A local
comparison found 19 exact registry package identities on this branch absent
from public `origin/main`; the query was not retried. No vulnerability query
was sent and no vulnerability conclusion is claimed.
The subsequent offline RustSec report is
`/tmp/autoapprover-rustsec-audit-20260923.json`, SHA-256
`11c18bf84c806cea56e975d8f0befed13a2b10fb51a48f085c9bded88699caf1`,
against unchanged `Cargo.lock` SHA-256
`51dc827a01e052cbc598847e4b504445bbe290df64d53b4b02f799f4a3295ace`.
It returned zero findings in that database snapshot, not a general vulnerability
clearance.

## Fresh upstream research and available access

The official release API returned stable `rust-v0.156.0`, release ID
`394061815`, published `2026-09-22T19:51:01Z`. Selected official asset digests
are retained in `compatibility/upstream-observed-2026-09-23.json`; that file is
explicitly discovery metadata, not native evidence. The exact tagged source
resolves to commit `fe74a774532af67b5a4a3dec03ce9469e17f89af` and was inspected in
`/tmp/autoapprover-codex-source-0.156.0`.

A later read-only check of GitHub's latest-full-release endpoint returned
`rust-v0.156.1`, release ID `394258789`, with Linux asset ID `582785771`,
size `107380357`, SHA-256
`aff46539a83aff86e3c62c592bce2c50d95391f9df289afaf03a50c01d14533d`,
and Windows asset ID `582786923`, size `323383088`, SHA-256
`70bcb05f9bf1a4e7306edd0cd1b57d02af3267ad02a34b26f45c8c4bb20a3301`.
The corrected watcher reconciled it against a temporary copy of the recorded
0.156.0 candidate without finding an intervening stable release. The checked-in
candidate remains at 0.156.0 so a future default-branch watcher run can open a
reviewable 0.156.1 PR. No PR or native qualification was produced here.

A later read-only watcher run again selected 0.156.1 and recorded the npm
parent plus six platform aliases from public registry metadata. A disposable
Linux install at `/tmp/autoapprover-npm-0.156.1-20260923` used an exact lock
with SHA-256 `6341237c5724e0ee0224b9743c9dfc89c9b1853e700caf77afaffd0b1d3951cb`.
The installed native npm executable had SHA-256
`0b2e9301d6100dddda3b9d5c80ebaeaa3a2f1962388f2f36f6b96a9f08b1f33f`.
These are temporary, non-live observations; the registry's signature audit
does not sign or certify this project's consumer artifact.
A separate temporary full 0.156.0 candidate record was reconstructed from
official release and npm metadata, then advanced read-only to 0.156.1. The
watcher re-fetched and matched that prior record's two native asset identities
and seven npm identities before writing the new temporary candidate. Synthetic
asset and npm mutations were rejected before a candidate write. No live
default-branch workflow or PR exercised this transition.
The checked-in 0.156.0 candidate was then upgraded from legacy schema 1 to
this full, still-unverified schema-2 metadata baseline. Its selected GitHub
asset digests and sizes match the separate official observation record.

Primary references: [official release](https://github.com/openai/codex/releases/tag/rust-v0.156.0),
[hook semantics](https://learn.chatgpt.com/docs/hooks),
[Windows sandbox](https://learn.chatgpt.com/docs/windows/windows-sandbox),
[tagged sandbox CLI](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/cli/src/debug_sandbox.rs),
[tagged Windows sandbox selection](https://github.com/openai/codex/blob/rust-v0.156.0/codex-rs/core/src/config/windows_sandbox_config.rs).
Current source exposes permission profiles and a shared daemon; the legacy
interactive verifier's old CLI arguments must be replaced before collecting
fresh hook evidence.

Read-only GitHub inspection confirmed admin access to
`slee7286/codex-autoapprover`, which is public and uses default branch `main`.
Another read-only API check found no `release-candidate` environment (404),
reported `main` as **not protected** (404), and returned an empty repository
ruleset list. The prepared provenance job will refuse to attest without the
environment's reviewer and protected-branch rules; no external setting was
changed by this check.
The first checkpoint was committed locally as `7a33bd5`. A push of
`feat/verified-release-foundation` to prepare a draft PR was rejected by
automatic approval review: it classified transferring the full branch to the
public repository as publication reserved for explicit user approval. No push
or PR was completed. Do not retry through another tool or route without
resolving that approval; continue independent local work. A reviewable PR body
is prepared at `/tmp/autoapprover-release-foundation-pr.md`.

The underlying Linux host reports Ubuntu 26.04, kernel
`7.0.0-31-generic`, x86_64; available tool execution remains isolated;
installed CLI reports `0.156.0` via an npm shim. The bundle layout is
recognized, but group-writable package files and directories prevent native
artifact admission. No Windows native result has been obtained.

An isolated Linux package exercise copied that exact installed npm tree into
a temporary owner-controlled directory, removed group/world write from every
copied file and directory, and used a disposable `CODEX_HOME`. `diagnose`
then recognized the real 0.156.0 native executable SHA-256
`78a11f06e0a2dda42d13fba1d50dc62e8cbdb2d5f69789722f4d4d99b5cdbe30`,
bundle SHA-256
`a746c99f6319e5208bcb4e20b465ece27b1c75683615c930facb73f7c230ceeb`,
npm launcher SHA-256
`61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70`,
and npm parent package SHA-256
`bd61fceec93b47cad25d48c7f20297d75f1289933fd1cf29ea8ce0aa02f2bc4f`.
The temporary tree was removed. This was identity discovery only: no
PermissionRequest, approval, consumer install or native qualification occurred.
One later verifier attempt used an isolated temporary Codex home containing
only a private copy of the configured authentication file. The host-access
PTY was detected as an isolated namespace and refused before launching a
child. The default PTY passed the earlier surface check but failed to create
the private broker socket (`Operation not permitted`) before launching a
child. Both temporary authentication copies were removed, and a subsequent
root-owner check now classifies that default PTY as an isolated namespace too.
An additional read-only host-access diagnosis inside a `script(1)`
pseudo-terminal also reported `isolated-namespace`; it did not start a Codex
child or run the verifier.
None of these attempts generated native hook evidence or changed live Codex settings.
Existing Windows 0.156.0 observations retain their original limits: elevated
setup also failed without this wrapper, while unelevated `Get-Location` worked;
neither proves hook compatibility, a long-path cause or a version regression.

## Completion audit and continuation ledger

| Original requirement | Evidence now | Required work still open |
| --- | --- | --- |
| 1. Exact certified compatibility only | Empty schema-2 manifest; whole-tuple equality; native bundle and npm launch-chain hashes; Unix group/world-write rejection; prepared Windows directory owner/DACL and reparse checks; artifact revocation; unsupported surfaces and legacy aliases fail closed | Certify final artifacts; execute and independently review Windows ACL and exe/cmd/ps1 paths on native hosts; harden consumer install permissions; verify effective sandbox/managed-policy behavior and updates during sessions; implement revocation delivery |
| 2. Fresh native Linux and Windows targets | Official stable metadata checked; historical Linux authority removed; Windows observations preserved accurately; available Linux PTYs refused before a live child | Obtain genuinely native positive/negative qualification of exact final Linux and Windows artifacts; retain every observed version/build; keep all other platforms/surfaces unarmed |
| 3. Runtime and independent security review | Parser, process, image, replay, ledger, slow-sender deadline, worker-reaping and nonce-bound loopback witness regressions pass on Linux; the blanket hook-trust bypass was removed; Windows verifier/probe Job Object containment and descendant/stalled-pipe regressions cross-compile only | Real shell/file edits and one-request allow/fallback; isolated hook composition/trust review; every advertised schema; native Windows job, stalled-pipe and hung-descendant tests; malicious descendants, PID/path races, abrupt termination; independent security review and documented residual boundary |
| 4. Install/reinstall/upgrade/rollback/uninstall | Existing TOML preservation plus embedded-manifest installer check; hardlinked/reparse config files, redirected directory chains and oversized input now fail closed; Linux artifact lifecycle passes disposable local tests with crash-journal simulations and a bounded staged-copy write failure; Windows artifact installer and two-ZIP exact-byte lifecycle rehearsal are prepared but unrun | Authenticated final Linux consumer package and exact-byte rehearsal; native Windows artifact lifecycle and PS 5.1/7 execution of prepared hardlink/junction cases; shims; homes/roots; Unicode/metacharacters/long paths; profiles/managed policy; ACL/lock/actual disk-full/power-loss/interruption matrix |
| 5. Default-branch detection/adaptation | Latest-full-release polling and bounded previous-tag scan read-only verified against 0.156.1; schema-3 records bind the Git tag object and source commit; exact native asset IDs/sizes/digests and seven npm tarball integrities retained; full prior asset/npm identity is rechecked on updates, with a read-only 0.156.0-to-0.156.1 rehearsal and drift-rejection fixtures; disposable Linux exact-lock install, signature audit and non-live probes passed; candidate code and trusted metadata tools are separate; candidate-branch metadata must equal a fresh official record; one remote commit is pinned through preflight/code checks/repair and the pushed repair commit is pinned for post-repair checks; preflight and setup failures cannot spend repair authority without a Rust-check failure artifact; only a newly opened PR is automatically repair-eligible, unchanged releases skip deleted-branch lookup and explicit dispatch can retry; candidate runners stream and compare downloads; source repair rejects a moved tag object or commit before running the agent; local multi-release fixtures queue one previously unhandled PR per poll and fail closed on missing baseline/history or changed open-PR metadata; prepared restricted-patch repair jobs separate the read-only agent from the write-token apply step | Activate and exercise reviewed workflow on main with a dedicated repair key; exercise oldest-first missed-release catch-up and moved/deleted tag refusal on the default branch, then measure backlog latency; exercise exact npm package verification on native Windows and in the actual workflow; verify changed/revoked assets end to end and deliver revocation to installed users; outage/rate-limit/recovery/schedule monitoring; demonstrate discovery-to-code-repair-to-native-validation PR; independent secret-boundary review and review-controlled promotion |
| 6. Durable native evidence | Schema-2 gate requires full targets, fresh source/binary digests, retained artifacts and independent identities; the experimental verifier has a local request witness and can retain an opt-in redacted, unqualified diagnostic after broker shutdown, but no live native run | Replace legacy verifier with unattended bounded disposable harness; obtain actual PermissionRequest, one allow, independent outcome, no prompt, negative/isolation/clean-state/cleanup evidence; retain reviewed schema-2 native records; independent release review |
| 7. Public distribution/protection | Development build and exact pending gate; ownership entries expanded; deterministic unqualified Linux archive with exact-byte install rehearsal; checksum-verified preliminary locked SPDX inventory and offline notice bundle with two missing top-level texts; exact-digest native build observation now required by the evidence gate and manual protected-environment candidate-provenance workflow prepared, with the Linux staging script rehearsed locally | Semantic release/changelog; final Linux and Windows consumer artifacts; reproducible inputs and linked component inventory; final per-artifact SBOM/notices and independent license/vulnerability review; execute/verify native provenance workflow; CI required review/branch and environment protections/private reporting/bot permissions; staged rollout/recovery/revocation; final exact-artifact installation and rollback |
| 8. Authorized autonomous work and publication control | Work continues on requested branch; no live user configuration changes or public release; automatic approval review rejected the attempted public branch push | Continue independent local work; obtain explicit publication approval before pushing the branch or preparing a public draft PR; final publication remains with the user |

**Completion is unproven and contradicted by the open items above.** The goal
must stay active. Do not turn this checkpoint, a cross-build or an empty
allowlist into a claim of release completion. The next work is the complete
artifact/launch adapter and isolated native harness, then consumer lifecycle,
update repair automation and protected release delivery. No new access or
hardware blocker is asserted while those independent workstreams remain.
