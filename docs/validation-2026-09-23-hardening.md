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
  Windows file handles deny write/delete sharing, but directory ACL and
  reparse-point validation is not implemented; Windows bundle admission
  explicitly fails closed pending native testing and independent review.
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
  normal approval. Both brokers now audit each parsed request before deciding;
  a denied or replayed request invalidates the verifier's one-invocation check.
  A malformed hook input that never reaches the broker is outside this count.
  Same-user malicious descendants remain an open review item.
- Probe output uses private temporary files rather than unbounded thread joins
  on inherited pipes. Unix probe process groups are terminated on completion or
  timeout. The isolated interactive verifier now requests no shared daemon and
  bounds and stops its child on timeout or interruption. On Unix it now starts
  the verification child in a separate process group and kills its descendants
  before evidence inspection or cleanup, including when the parent exits first.
  This has synthetic regression coverage; native Codex testing is still needed.
  Windows verifier descendant termination still needs implementation and native
  testing.
- The schema-2 release gate compares the entire compiled manifest and evidence
  targets, includes the manifest in source hashing, requires consumer/upstream
  digests, retained artifact hashes, independent review identities and all
  named checks. Reports expire for release qualification after 30 days.
- The Windows source installer verifies that its source manifest equals the
  installed executable's embedded manifest before configuration changes.
- A Linux prebuilt-artifact installer now checks an expected SHA-256, embedded
  manifest equality and executable health before selecting a release. It uses
  private directories, digest-addressed releases, a lock and atomic symlink
  updates; rollback and uninstall journals permit recovery after interruption.
  It has no authenticated public artifact to install yet.
- A deterministic Linux development archive includes the exact installer,
  binary, manifest, licence, README and per-file digest metadata. Two local
  builds compared byte-for-byte, and the extracted executable installed and
  uninstalled from a disposable directory. Its checksum is unsigned and its
  metadata explicitly says unqualified.
- The preliminary SPDX 2.3 locked-dependency inventory lists 89 exact packages
  and 137 relationships. All 88 third-party archive checksums matched
  `Cargo.lock`; declared licenses were read from those archives. It passed the
  official SPDX 2.3 JSON schema locally, but no independent license or
  vulnerability conclusion has been made.
- A manual main-branch workflow now prepares native Linux and Windows
  candidate binaries and checksums. Separate jobs gate the exact downloaded
  bytes; a protected-environment job can attest candidate build provenance
  without implying approval compatibility. It checks environment review and
  branch rules before requesting attestations. The workflow has not run, and
  its PowerShell staging and native release gates remain untested on Windows.

## Verification performed

| Check | Result and scope |
| --- | --- |
| `cargo test --locked --all-targets` | 68 unit tests and 22 integration tests passed on Linux with host Unix-socket access; synthetic regression evidence only. New cases cover denied/replayed broker audit accounting and Unix descendant cleanup. |
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo clippy --locked --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings` | Passed; compile/lint only, no Windows execution |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 33 tests passed, including synthetic repair, checksum-verified dependency inventory, bounded latest-release discovery and missed-release rejection; none entered production evidence |
| `cargo build --release --locked --bin codex-autoapprover` | Local development executable built |
| `release_gate.py --binary ...` | Exact compiled/source manifest equality passes; production remains blocked |
| `release_gate.py --require-ready --binary ...` | Correctly rejects incomplete qualification |
| `verify-manifest --manifest compatibility/manifest.json` | Installed/source manifest comparison passes for the local binary |
| `scripts/test-install-linux.sh target/release/codex-autoapprover` | Disposable Linux install, identical reinstall, synthetic changed-artifact upgrade, rollback, tamper/unmanaged-path rejection, uninstall and interrupted-operation recovery passed; Codex home content stayed unchanged |
| `scripts/test-package-linux.sh target/release/codex-autoapprover` | Two development archives were byte-identical; checksum and per-file digests matched; exact extracted bytes installed, executed and uninstalled in a disposable directory |
| `python3 scripts/locked_sbom.py --offline --output /tmp/...` | Generated 89-package, 137-relationship SPDX 2.3 locked inventory from checksum-verified crate archives; local official-schema validation passed |
| Candidate provenance workflow static review | YAML structure, main-only dispatch, token permissions, job order, Bash and inline Python syntax passed locally; no GitHub run, environment approval, provenance signature or Windows PowerShell execution occurred |
| Disposable `verify-local-hook` attempt | No live Codex child started: host-access PTY was classified `isolated-namespace`; default PTY could not create the private broker socket. Both copied-auth temporary homes were removed. No PermissionRequest, allow or command outcome exists. |
| `git diff --check` | Passed |

The first sandboxed test run could not create private Unix sockets. Running the
same suite with host socket access passed. New regression coverage includes
every tuple-field mismatch, revocation, duplicate manifest fields, historical
version spoofing, native-image replacement, symlink retargeting/hardlinks,
hung probes/descendant-held output, session rebinding/replay and concurrent
single-allow consumption. These results do not prove native Codex behavior.

Local development artifact: `target/release/codex-autoapprover`, SHA-256
`0daef6779eff5e6db82bb5fe04c8143f243ee60943019315a50093aa4d271453`.
This is neither a signed consumer package nor a qualified production binary.
Rebuilds after further source edits require recording a new digest.

Latest local development archive:
`/tmp/autoapprover-dev-package-20260923-v6/codex-autoapprover-0.1.0-linux-x86_64-dev.tar.gz`,
SHA-256 `59a1614a5ef82e34d00138d3e78dba2ab6103a985ff5b2db99b0e6e5dfc3ab7c`.
Its recorded source digest is
`400c1f23c0fef1ab9a90273b2ca179e82ee5f72c30b8ac3e3411d54603cf969d`.
It is unsigned, unqualified and stored only in temporary local storage.

The matching preliminary locked-dependency inventory is
`/tmp/autoapprover-locked-dependencies-v6.spdx.json`, SHA-256
`a3207de4d1352494bb7d742701d2ab738464a0a8c6d2e9e6146872549ee38799`.
It passed the locally retained official SPDX 2.3 schema. It is not an
attestation, a binary-specific SBOM or an independent dependency review.

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
Neither attempt generated native hook evidence or changed live Codex settings.
Existing Windows 0.156.0 observations retain their original limits: elevated
setup also failed without this wrapper, while unelevated `Get-Location` worked;
neither proves hook compatibility, a long-path cause or a version regression.

## Completion audit and continuation ledger

| Original requirement | Evidence now | Required work still open |
| --- | --- | --- |
| 1. Exact certified compatibility only | Empty schema-2 manifest; whole-tuple equality; native bundle and npm launch-chain hashes; group/world-write rejection; artifact revocation; unsupported surfaces and legacy aliases fail closed | Certify final artifacts; finish/test exe/cmd/ps1 and other package layouts on native hosts; harden consumer install permissions; verify effective sandbox/managed-policy behavior and updates during sessions; implement revocation delivery |
| 2. Fresh native Linux and Windows targets | Official stable metadata checked; historical Linux authority removed; Windows observations preserved accurately; available Linux PTYs refused before a live child | Obtain genuinely native positive/negative qualification of exact final Linux and Windows artifacts; retain every observed version/build; keep all other platforms/surfaces unarmed |
| 3. Runtime and independent security review | Parser, process, image, replay, ledger, timeout and concurrency regressions pass | Real shell/file edits and one-request allow/fallback; hook composition/trust; every advertised schema; malicious descendants, PID/path races, abrupt termination and Windows hung descendants; independent security review and documented residual boundary |
| 4. Install/reinstall/upgrade/rollback/uninstall | Existing TOML preservation plus embedded-manifest installer check; Linux artifact lifecycle passes disposable local tests with crash-journal simulations | Authenticated final Linux consumer package and exact-byte rehearsal; Windows artifact lifecycle; native PS 5.1/7; shims; homes/roots; Unicode/metacharacters/long paths; profiles/managed policy; ACL/reparse/hardlink/lock/disk-full/interruption matrix |
| 5. Default-branch detection/adaptation | Latest-full-release polling and bounded previous-tag scan verified against 0.156.1; exact native asset IDs/sizes/digests retained; candidate runners stream and compare downloads; changed metadata and multi-release gaps fail closed; prepared restricted-patch repair jobs separate the read-only agent from the write-token apply step | Activate and exercise reviewed workflow on main with a dedicated repair key; handle missed stable releases automatically rather than only alarming; verify installed npm bundle integrity and changed/revoked assets end to end; outage/rate-limit/recovery/schedule monitoring; demonstrate discovery-to-code-repair-to-native-validation PR; independent secret-boundary review and review-controlled promotion |
| 6. Durable native evidence | Schema-2 gate requires full targets, fresh source/binary digests, retained artifacts and independent identities | Replace legacy verifier with unattended bounded disposable harness; obtain actual PermissionRequest, one allow, independent outcome, no prompt, negative/isolation/clean-state/cleanup evidence; retain durable native records; independent release review |
| 7. Public distribution/protection | Development build and exact pending gate; ownership entries expanded; deterministic unqualified Linux archive with exact-byte install rehearsal; checksum-verified preliminary locked SPDX inventory; manual protected-environment candidate-provenance workflow prepared and statically checked | Semantic release/changelog; final Linux and Windows consumer artifacts; reproducible inputs; binary-specific SBOM and independent license/vulnerability review; execute/verify native provenance workflow; CI required review/branch and environment protections/private reporting/bot permissions; staged rollout/recovery/revocation; final exact-artifact installation and rollback |
| 8. Authorized autonomous work and publication control | Work continues on requested branch; no live user configuration changes or public release | Continue independent work and authorized draft PRs; identify specific unavoidable prerequisites only after independent work is exhausted; final publication remains with the user |

**Completion is unproven and contradicted by the open items above.** The goal
must stay active. Do not turn this checkpoint, a cross-build or an empty
allowlist into a claim of release completion. The next work is the complete
artifact/launch adapter and isolated native harness, then consumer lifecycle,
update repair automation and protected release delivery. No new access or
hardware blocker is asserted while those independent workstreams remain.
