# Exact compatibility hardening — 2026-09-23

This is an implementation checkpoint after foundation commit `2c54080`, not a
production qualification. The complete objective remains
[production-goal.md](production-goal.md), including all eight workstreams and
all named native/install/release gates. No part of that objective is waived by
this checkpoint. Previous foundation checks were progress; this continuation
made additional code, gate, test and documentation changes.

## Current authoritative state

- The embedded schema-1 `compatibility/manifest.json` has **zero certified
  targets**. Historical Linux 0.151.0 no longer grants production authority.
- Runtime admission compares version, OS, architecture, exact OS release and
  build, explicitly selected sandbox, foreground CLI surface, protocol, tool
  and native executable SHA-256. Legacy automatic settings cannot bypass it.
- Linux launches the held executable inode through `/proc/self/fd`; Windows
  holds a file handle without write/delete sharing. The brokers recheck the
  configured path, file identity and actual running process image.
- Native observation rejects known SSH/remote, IDE, WSL, container and isolated
  namespace environments. Missing host facts remain inconclusive. These checks
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
  normal approval. Same-user malicious descendants remain an open review item.
- Probe output uses private temporary files rather than unbounded thread joins
  on inherited pipes. Unix probe process groups are terminated on completion or
  timeout. Windows descendant termination still needs implementation/testing.
- The schema-2 release gate compares the entire compiled manifest and evidence
  targets, includes the manifest in source hashing, requires consumer/upstream
  digests, retained artifact hashes, independent review identities and all
  named checks. Reports expire for release qualification after 30 days.
- The Windows source installer verifies that its source manifest equals the
  installed executable's embedded manifest before configuration changes.

## Verification performed

| Check | Result and scope |
| --- | --- |
| `cargo test --locked --all-targets` | 63 unit tests and 22 integration tests passed on Linux with host Unix-socket access; synthetic regression evidence only |
| `cargo fmt --check` | Passed |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | Passed |
| `cargo clippy --locked --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings` | Passed; compile/lint only, no Windows execution |
| `python3 -m unittest discover -s scripts -p 'test_*.py'` | 11 tests passed; synthetic gate fixtures never entered production evidence |
| `cargo build --release --locked --bin codex-autoapprover` | Local development executable built |
| `release_gate.py --binary ...` | Exact compiled/source manifest equality passes; production remains blocked |
| `release_gate.py --require-ready --binary ...` | Correctly rejects incomplete qualification |
| `verify-manifest --manifest compatibility/manifest.json` | Installed/source manifest comparison passes for the local binary |
| `git diff --check` | Passed |

The first sandboxed test run could not create private Unix sockets. Running the
same suite with host socket access passed. New regression coverage includes
every tuple-field mismatch, revocation, duplicate manifest fields, historical
version spoofing, native-image replacement, symlink retargeting/hardlinks,
hung probes/descendant-held output, session rebinding/replay and concurrent
single-allow consumption. These results do not prove native Codex behavior.

Local development artifact: `target/release/codex-autoapprover`, SHA-256
`a58e4f58e70bb7e768d93ad173d0b99f434b7d4862284e7177b2b506327e620a`.
This is neither a signed consumer package nor a qualified production binary.
Rebuilds after further source edits require recording a new digest.

## Fresh upstream research and available access

The official release API returned stable `rust-v0.156.0`, release ID
`394061815`, published `2026-09-22T19:51:01Z`. Selected official asset digests
are retained in `compatibility/upstream-observed-2026-09-23.json`; that file is
explicitly discovery metadata, not native evidence. The exact tagged source
resolves to commit `fe74a774532af67b5a4a3dec03ce9469e17f89af` and was inspected in
`/tmp/autoapprover-codex-source-0.156.0`.

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
The first checkpoint was committed locally as `7a33bd5`. A push of
`feat/verified-release-foundation` to prepare a draft PR was rejected by
automatic approval review: it classified transferring the full branch to the
public repository as publication reserved for explicit user approval. No push
or PR was completed. Do not retry through another tool or route without
resolving that approval; continue independent local work. A reviewable PR body
is prepared at `/tmp/autoapprover-release-foundation-pr.md`.

Available native Linux is Ubuntu 26.04, kernel `7.0.0-31-generic`, x86_64;
installed CLI reports `0.156.0` via an npm shim. The shim is not presently
admitted as a native executable. No Windows native result has been obtained.
Existing Windows 0.156.0 observations retain their original limits: elevated
setup also failed without this wrapper, while unelevated `Get-Location` worked;
neither proves hook compatibility, a long-path cause or a version regression.

## Completion audit and continuation ledger

| Original requirement | Evidence now | Required work still open |
| --- | --- | --- |
| 1. Exact certified compatibility only | Empty manifest; whole-tuple equality; native image checks; unsupported surfaces and legacy aliases fail closed | Certify final artifacts; resolve npm/exe/cmd/ps1 launch chains and helper/resource identity; verify effective sandbox/managed-policy behavior and updates during sessions; implement tested revocation delivery |
| 2. Fresh native Linux and Windows targets | Official stable metadata checked; historical Linux authority removed; Windows observations preserved accurately | Native positive/negative qualification of exact final Linux and Windows artifacts; retain every observed version/build; keep all other platforms/surfaces unarmed |
| 3. Runtime and independent security review | Parser, process, image, replay, ledger, timeout and concurrency regressions pass | Real shell/file edits and one-request allow/fallback; hook composition/trust; every advertised schema; malicious descendants, PID/path races, abrupt termination and Windows hung descendants; independent security review and documented residual boundary |
| 4. Install/reinstall/upgrade/rollback/uninstall | Existing TOML preservation plus embedded-manifest installer check | Consumer artifact installer, transactional upgrade/rollback/uninstall and recovery; native PS 5.1/7; shims; homes/roots; Unicode/metacharacters/long paths; profiles/managed policy; ACL/reparse/hardlink/lock/disk-full/interruption matrix |
| 5. Default-branch detection/adaptation | Existing watcher/synthetic probes; admin access confirmed | Activate reviewed workflow on main; official artifact integrity and changed/revoked asset handling; pagination/outage/rate-limit/recovery/schedule monitoring; bounded repair worker; demonstrated discovery-to-code-repair-to-native-validation PR; review-controlled promotion and secret isolation |
| 6. Durable native evidence | Schema-2 gate requires full targets, fresh source/binary digests, retained artifacts and independent identities | Replace legacy verifier with unattended bounded disposable harness; obtain actual PermissionRequest, one allow, independent outcome, no prompt, negative/isolation/clean-state/cleanup evidence; retain durable native records; independent release review |
| 7. Public distribution/protection | Development build and exact pending gate; ownership entries expanded | Semantic release/changelog; final consumer binaries/installers; reproducible inputs; SBOM/license/dependency review; checksums/provenance/signing; CI required review/branch and environment protections/private reporting/bot permissions; staged rollout/recovery/revocation; exact-artifact installation and rollback |
| 8. Authorized autonomous work and publication control | Work continues on requested branch; no live user configuration changes or public release | Continue independent work and authorized draft PRs; identify specific unavoidable prerequisites only after independent work is exhausted; final publication remains with the user |

**Completion is unproven and contradicted by the open items above.** The goal
must stay active. Do not turn this checkpoint, a cross-build or an empty
allowlist into a claim of release completion. The next work is the complete
artifact/launch adapter and isolated native harness, then consumer lifecycle,
update repair automation and protected release delivery. No new access or
hardware blocker is asserted while those independent workstreams remain.
