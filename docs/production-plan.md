# Production release plan

Status: implementation groundwork, **not production-ready**. Last reviewed 2026-09-23.
The continuation prompt is [production-goal.md](production-goal.md).

## Decisions and evidence

1. General automatic approval requires an exact reviewed Codex version and OS. The old `automatic` setting now has strict semantics; a capability probe cannot enable a new version. Unsupported installations use ordinary Codex with broker credentials removed. A future supported matrix must also bind architecture, OS build/distro, sandbox implementation, launch surface, protocol, and the actual Codex binary identity.
2. The only historical positive entry is Linux/local CLI/Codex 0.151.0. It is not fresh qualification of this implementation. Windows 0.156.0 is unverified: the user reproduced elevated sandbox runtime validation failing on a 283-character directory path, including without the wrapper; the unelevated `Get-Location` test succeeded. The underlying Windows API error was not captured. Do not describe the root cause as a proven long-path bug or a proven update regression.
3. Installation preserves sandbox configuration by default. `-WindowsSandbox unelevated` explicitly enables the previously requested workaround and retains it on subsequent default reinstalls. The runtime launcher never edits settings. The new TOML editor handles quoted/dotted keys, inline tables, multiline strings, unrelated arrays, backups and repeated application. Native replacement, ACL and rollback behavior still needs Windows testing.
4. Updates initiate discovery, candidate testing, repairs and review. They never automatically broaden the allowlist. General code repair cannot be guaranteed by a version bump. A repair agent must work on a candidate branch, have bounded authority, and pass the same evidence gate as a human change.
5. "Everyone can use it" means a public product with an explicit supported matrix and a clear unsupported response. It does not mean untested platforms become supported. No finite test suite proves every conceivable edge case; complete the matrix below and document residual limits.

## Research and design basis

- OpenAI documents `PermissionRequest` decisions and the normal approval flow when no hook decides. Tool inputs differ; a shell example does not establish edit/MCP compatibility. [Official hooks documentation](https://learn.chatgpt.com/docs/hooks)
- Elevated and unelevated Windows sandboxes have different isolation mechanisms. The latter is a documented fallback, not a universal installer default. [Official Windows sandbox documentation](https://learn.chatgpt.com/docs/windows/windows-sandbox)
- Repository webhooks need owner/admin access. We cannot install an upstream webhook in `openai/codex`; a scheduled release-API watcher is the available mechanism. [GitHub webhook permissions](https://docs.github.com/en/webhooks/using-webhooks/creating-webhooks)
- Schedules run from the default branch, can be delayed/dropped and can be disabled after repository inactivity. Use manual dispatch plus external heartbeat monitoring; do not advertise instant or guaranteed update detection. [GitHub workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- The release API provides stable/draft/prerelease metadata. Discovery uses bounded pagination, numeric version validation, explicit errors and no release-body execution. [GitHub releases API](https://docs.github.com/en/rest/releases/releases)
- Token-created PR checks can require workflow approval. Candidate probes run in the watcher workflow itself; reviewed code changes still need full PR CI. [GitHub workflow triggering](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow)
- Workflow actions are pinned to commit IDs read from their upstream repositories. Repository protections and independent review remain necessary. [GitHub Actions security](https://docs.github.com/en/actions/reference/security/secure-use)
- Configuration editing uses a TOML parser that preserves comments and formatting rather than interpreting configuration as lines. Some formatting may normalize; the original is backed up exactly. [toml_edit documentation](https://docs.rs/toml_edit/latest/toml_edit/)

## Implemented in this worktree

- Strict version/OS admission at launch and runtime request handling. Historical `automatic` flags/environment values cannot bypass it.
- Separate, exact-command-only experimental verifier; no candidate can gain general approval through verifier metadata.
- Manual fallback removes inherited token, socket, protocol and audit variables.
- Ambiguous version banners rejected; documented nullable descriptions accepted.
- Explicit Windows TOML configuration command and installer switch; no blanket sandbox downgrade.
- Six-hour release polling, optional draft PR creation, native-runner synthetic tests and non-live CLI probes. New metadata remains unverified. Existing open/closed candidate PRs are not overwritten.
- Release policy, evidence/source integrity validation, and a manually triggered readiness workflow. `ready: false` and outstanding blockers intentionally prevent production qualification.
- Dependency update configuration, pinned workflow actions and code-owner entries. These files do not enable repository rules by themselves.

## Remaining work, in order

| Workstream | Completion evidence |
| --- | --- |
| Release identity | Exact supported version/OS/architecture/build/sandbox/surface and signed upstream binary digests; enforce the same manifest in the launcher, broker, installer and release tooling. Eliminate broad OS-family certification and version-output-only trust. |
| Execution health | Native shell and file-edit smoke checks under the selected sandbox before general arming; timeout and readable repair diagnosis. Reproduce Windows failure in an isolated image if possible; cover long paths and capture the native error. |
| Process boundary | Independent review of descendant forgery, replay/session binding, PID reuse, race conditions, executable replacement, same-user attacker limits, abrupt termination, leaked credentials and concurrent brokers. Never hide an unresolved exploitable false allow. |
| Protocol coverage | Native positive/negative evidence for every advertised tool. If only Bash is validated, state that clearly; unsupported edit/MCP requests must use normal approval. |
| Installation | Clean machines, preexisting installs, locked binaries, Windows PowerShell 5.1/7, executable/cmd/ps1 shims, Unicode/spaces/metacharacters/long paths, custom/relative CODEX_HOME and Cargo roots, TOML BOM/CRLF, inline/dotted keys, read-only/symlink/reparse/hardlink files, ACL preservation for backup and destination, disk-full and interruption recovery. Define profile/managed-policy precedence. |
| Update automation | Exercise actual scheduled run and dispatch; rate limiting, outage, missed releases, pagination window exhaustion, moved/deleted tags/assets, duplicate events, branch/PR recovery, changed metadata, expired credentials and inactive-schedule alarms. Pin exact upstream package/artifact integrity. |
| Automated repairs | Add a protected repair worker that receives a bounded task and untrusted upstream diffs; writes only a candidate branch, retains redacted evidence, reruns native tests, and creates/updates a reviewable PR. Limit retries/costs; escalate inconclusive cases without enabling support. No arbitrary upstream text execution, unattended allowlist promotion, or signing credentials in repair jobs. |
| Distribution | Versioning/changelog, reproducible per-platform builds, SBOM, dependency/license audit, checksums and verifiable provenance/signing, protected publishing environment, staged rollout, rollback/revocation, installer/uninstaller and public support docs. |
| Public qualification | Native supported-platform matrix completed against final artifacts; protected PR checks and independent security/release review; fresh evidence hashes; clean install/upgrade/rollback rehearsal from consumer artifacts. Only then mark ready and prepare the public release. |

## Evidence and release gate

`compatibility/release-policy.json` records intended production readiness separately from historical adapter evidence. Store redacted, native live reports under `compatibility/evidence/`; never store credentials, raw private commands, session secrets or user configuration. The report must include:

- `schema_version: 1`, `kind: "native-live"`, exact `codex_version`, `os`, `arch`, `os_release`, `sandbox`;
- `source_sha256` from `python scripts/release_gate.py --print-source-digest`, `codex_binary_sha256`, producer, a different reviewer, `review_decision: "approved"`, and a durable HTTPS `run_url`;
- every named check in `scripts/release_gate.py:CHECKS`, each with an independently substantiated result, plus artifact references/log hashes in the report.

Reference each report and its SHA-256 in the policy. The gate verifies code/evidence integrity, required results and consistency with `support-matrix`; it cannot establish that a human assertion is true. Branch protection, native execution and review supply that trust. Code/dependency/test/workflow changes invalidate the source digest. Evidence from a different release cannot be silently reused.

The current `support-matrix` reports historical OS-family entries. Before public release, replace this with the fully bound runtime manifest and extend gate equality to every dimension. This is an explicit blocker; the gate is groundwork, not proof of production quality.

## Repository activation

Merge the reviewed changes to the default branch before expecting scheduled discovery. Enable Actions and permission for the bot to create PRs. Configure required code-owner review for compatibility, security, workflows and installers; disallow direct/force pushes to release branches. Set required native CI checks and protect signing/publishing environments. Verify private vulnerability reporting and establish a support/incident contact. Deploy an external monitor for watcher success if update-detection latency matters.

No workflow, repository setting, signing credential or public release was activated by preparing these files locally. Manual commands:

```sh
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/watch_codex.py                         # metadata only, network read
python scripts/release_gate.py                       # structural validation
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo build --release --locked --bin codex-autoapprover
python scripts/release_gate.py --require-ready --binary target/release/codex-autoapprover
```

The last command must fail while qualification remains incomplete. A failed check is a blocker, not a reason to weaken the gate.
