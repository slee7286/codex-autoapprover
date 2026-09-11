<!-- Generated from docs/distribution-roadmap.json by validate_distribution_roadmap; do not edit. -->

# Distribution roadmap

- Schema version: `1.0`
- Roadmap revision: `4`
- Repository: `slee7286/codex-autoapprover`
- Inspected source commit: `296008527103e98b9d9f9f20fe6d4e8508346b21`
- Source branch: `main`
- Roadmap branch: `feat/distribution-roadmap`
- Current milestone: `M1`
- Next executable task: `M1-T3`

## Objective

Plan and then implement a trustworthy, user-scoped, installable Windows x64 and Linux x64 release of codex-autoapprover with startup update checks enabled by default but update installation requiring explicit consent, while preserving the existing Codex wrapper, hook authorization, fallback, arguments, cwd, terminal I/O, configuration, and exit-status behavior.

## Scope

- Prebuilt native Windows x64 and Linux x64 packages that do not require Rust, Cargo, Git, or administrator privileges at runtime or installation.
- A documented codexa or codex-autoapprover run wrapper; the original codex command remains untouched and is never shadowed or replaced.
- Startup detection of the actual Codex executable and version, version-change-triggered applicable-release checks, consent, activation, rollback, and uninstall.
- Bounded release metadata, applicability selection, authenticated assets, user-scoped state, rate-limit backoff, concurrent-check coordination, and local compatibility outcomes.
- Native Windows and native Linux tests, release automation, provenance, and a first-public-release handoff.

## Non-goals

- Implementing the updater, installers, packaging, or release automation in this roadmap-only change.
- Replacing, patching, or shadowing the official codex executable or changing Codex authentication, rules, hooks, or user data.
- Supporting every Linux distribution, libc, CPU architecture, macOS, WSL, containers, IDE/desktop surfaces, remote sessions, or Codex cloud in the initial release.
- Treating local observations, successful Codex exit, capability probes, or roadmap completion as project-wide reviewed compatibility.
- Starting live verification, installing anything, publishing a release, tagging a release, or changing persistent Codex configuration during roadmap work.

## Startup decision table

| State | Condition | Wrapper action | Codex action | Outcome |
| --- | --- | --- | --- | --- |
| Wrapper launch | codexa or codex-autoapprover run starts before the official Codex child | Resolve the actual installed codex executable, version, platform, local-CLI surface, arguments, cwd, and whether startup checks are disabled; updater logic stays in the wrapper process. | Codex has not started. | Continue to version-change, unresolved-state, explicit-check, or disabled-check handling. |
| Startup check eligibility | Checks are enabled and the Codex version changed, compatibility is unresolved, or the user requested update --check; otherwise a backoff window suppresses the network request. | Coordinate with other launches, consult the bounded cache/validator state, and check the fixed release origin for a newer applicable release. | Codex has not started. | A check may produce applicable, no-applicable-release, unavailable, malformed, incompatible, or backoff results. |
| Applicable release found | Authenticated metadata selects a newer stable asset for the exact native target and supported Codex tuple. | In an interactive terminal offer Install, Continue this time, and Skip this release with current/new versions, compatibility status, and release-notes link. | Codex has not started. | Install enters bounded verification/activation; the other choices continue with the installed implementation. |
| Noninteractive or no consent | Input is noninteractive, the user chooses Continue this time, or the user declines installation. | Do not prompt or consume Codex input; record only a fixed local update outcome and continue with the installed automatic compatibility policy. | Start Codex normally after the wrapper decision. | No update is installed and normal approval fallback remains available. |
| Skip this release | The user explicitly skips the offered release. | Persist a skip scoped to the exact installed Codex version and release version; do not suppress later Codex-version changes or a different applicable release. | Start Codex normally after the wrapper decision. | The same release is not offered again for that Codex version unless explicitly requested; a Codex version change reconsiders applicability. |
| Unavailable, malformed, incompatible, or backoff result | The service times out/is unavailable, metadata is invalid, no applicable asset exists, the release is a prerelease/unsupported target, or a server-directed backoff is active. | Keep the installed version and record a fixed-category local update-check result without treating it as hook compatibility evidence. | Start Codex normally after the wrapper decision. | The installed automatic compatibility policy is attempted if eligible; otherwise Codex uses ordinary approval behavior. |
| Update activation failure | Download, authentication, hash, extraction, health check, atomic activation, or rollback preparation fails before Codex starts. | Discard incomplete staging, retain the known-good active version, and report a fixed-category local update failure. | Start Codex with the known-good installed version. | A failed update never blocks ordinary Codex startup or replaces the active payload. |
| Capability check | The installed Codex/version tuple is eligible for an automatic attempt and the bounded non-live hook capability probe is run. | Arm the existing broker/hook path only when its existing identity, ancestry, session, cwd, schema, tool, and exact authorization checks pass. | Start Codex with the wrapper's inherited arguments, cwd, terminal I/O, environment, and exit propagation. | Capability success is not hook success and does not promote project-wide verified support. |
| Hook/session outcome | A session either produces a genuine hook exchange, produces no hook invocation, or encounters a compatibility/transport/protocol rejection after Codex starts. | Record one fixed local category distinguishing capability success, hook success, no hook invocation, hook incompatibility, and command execution failure. | Never restart Codex, replay a command, or change the started session; preserve ordinary approval fallback. | Only a genuine authenticated hook exchange is hook success; a successful Codex exit alone is insufficient. |
| Command execution failure | The Codex child or requested command exits unsuccessfully after startup. | Propagate the child exit status and retain the local outcome category; do not retry by replaying the session or command. | The already-started Codex session ends once. | Command failure is never converted into compatibility success or an update decision. |

## Startup state transitions

| From | Event | To | Effect |
| --- | --- | --- | --- |
| wrapper_start | resolve official codex and version | startup_check_or_compatibility | Capture the version-change and unresolved-state inputs before the child starts. |
| startup_check_or_compatibility | check enabled and eligible, with no active backoff or another owner | release_selection | Perform one bounded coordinated check; a Codex-version change and unresolved state take precedence over the normal cache interval. |
| startup_check_or_compatibility | check disabled, unchanged resolved state, or backoff | compatibility_policy | Skip network and retain the installed compatibility policy. |
| release_selection | applicable release and interactive consent | activation_or_compatibility_policy | Install only after explicit consent; Continue this time and Skip this release continue without installation. |
| release_selection | noninteractive, unavailable, malformed, incompatible, or declined | compatibility_policy | Do not prompt or consume Codex input; continue with the installed version. |
| activation_or_compatibility_policy | activation succeeds before Codex launch | codex_launch | If activation needs a restart, pass one one-shot internal wrapper marker bound to the candidate release/digest; the restarted wrapper consumes and clears it before launching exactly one Codex child with preserved args/cwd/stdio, and a repeated or invalid marker bypasses restart and uses the known-good payload. |
| activation_or_compatibility_policy | activation fails or capability check is inconclusive | codex_launch | Use the known-good installed version and leave automatic approval unarmed when capability checks fail. |
| codex_launch | hook success, no hook invocation, hook incompatibility, or child command failure | session_exit | Record the fixed category, preserve ordinary approval fallback, and never replay or restart the started session. |

## Initial support targets

| Target | Triple | Proposed runtime floor | Package | Status | Native validation |
| --- | --- | --- | --- | --- | --- |
| native Windows x64 local CLI | `x86_64-pc-windows-msvc` | Windows 10 22H2 (build 19045) or later, user-scoped installation, no administrator privilege | zip archive plus PowerShell installer | `proposed_not_validated` | `M4-T3`, `M6-T2` |
| native Linux x64 local CLI | `x86_64-unknown-linux-gnu` | glibc 2.31 or later on a Linux system with /proc and flock; musl, other libc families, and other architectures are outside the initial target | tar.gz archive plus POSIX shell installer | `proposed_not_validated` | `M4-T3`, `M6-T2` |

## Installation ownership

### Windows

- Entry point: `%LOCALAPPDATA%/codex-autoapprover/bin/codexa.exe`
- Immutable payloads: `%LOCALAPPDATA%/codex-autoapprover/versions/<release>/`
- Active pointer: `%LOCALAPPDATA%/codex-autoapprover/state/active.json`
- Staging: `%LOCALAPPDATA%/codex-autoapprover/staging/`
- Cache: `%LOCALAPPDATA%/codex-autoapprover/cache/`
- Rollback: `%LOCALAPPDATA%/codex-autoapprover/rollback/`
- Ownership: The stable launcher is owned by the installer and never replaced while a child runs; immutable versioned payloads are added, and active.json is atomically replaced.

### Linux

- Entry point: `${XDG_DATA_HOME:-~/.local/share}/codex-autoapprover/bin/codexa`
- Immutable payloads: `${XDG_DATA_HOME:-~/.local/share}/codex-autoapprover/versions/<release>/`
- Active pointer: `${XDG_STATE_HOME:-~/.local/state}/codex-autoapprover/active.json`
- Staging: `${XDG_DATA_HOME:-~/.local/share}/codex-autoapprover/staging/`
- Cache: `${XDG_CACHE_HOME:-~/.cache}/codex-autoapprover/`
- Rollback: `${XDG_DATA_HOME:-~/.local/share}/codex-autoapprover/rollback/`
- Ownership: The stable launcher is owned by the installer; immutable versioned payloads and an atomically replaced active pointer avoid replacing a running executable.

## Release trust model

- **Metadata:** Use TUF 1.0 repository metadata with a pinned root.json, signed timestamp/snapshot/targets roles, bounded metadata/target sizes, and a persistent metadata datastore. The metadata selects an asset; it never authorizes a hook.
- **Bootstrap:** The initial installer and wrapper are obtained from the documented GitHub release origin over HTTPS and carry the reviewed public TUF root. Bootstrap provenance is an explicit user-visible trust boundary; a checksum fetched from the same origin as a binary is not independent publisher authentication.
- **Signing thresholds:** Use a 2-of-3 offline root-key threshold and a 2-of-3 targets-key threshold; timestamp/snapshot metadata may be produced by a restricted release workflow but cannot change a target hash or authorize an unlisted asset.
- **Asset integrity:** Accept only a target whose authenticated metadata matches exact length, hash, OS, architecture, runtime, package format, release version, provenance, and release-notes origin; reject redirects/origins outside the allowlist.
- **Expiration and replay:** Enforce safe metadata expiration, retain the highest trusted metadata versions in persistent state, and reject expired metadata, version rollback, stale snapshots, and downgrade attempts. A network failure continues with the installed version but never installs cached expired metadata.
- **Key rotation and revocation:** Rotate root keys through a new root metadata version signed by the existing and replacement threshold; remove compromised keys in that chain. If the trusted root chain cannot be advanced, stop updates and require a manually obtained wrapper/root refresh rather than silently resetting trust.
- **Rollback:** Rollback is an explicit user action to a retained locally installed payload whose authenticated metadata and health record are still available; remote downgrade is rejected and rollback never replays a Codex session.
- **Authorization boundary:** Release metadata and update state cannot change the compatibility registry, process/session binding, cwd, schema, tool, exact-command, broker, or fail-closed authorization checks.
- **Future maintainer actions:**
  - Choose the release owners and record the public root-key fingerprints in a reviewed bootstrap artifact; do not generate or store keys in this repository task.
  - Generate root and targets keys offline with the chosen 2-of-3 threshold and document secure backup, rotation, and emergency revocation procedures.
  - Configure a least-privilege GitHub Actions environment for restricted timestamp/snapshot signing and release publication only after the implementation and workflow review; upload secrets only as a separate maintainer action.
  - Run a staging rotation/revocation drill and publish the initial authenticated metadata only after M5 release automation and M6 validation are complete.

## Reviewed release libraries

| Purpose | Crate | Observed docs version | Official documentation | Decision |
| --- | --- | --- | --- | --- |
| Release metadata verification | `tough` | `0.24.0` | https://docs.rs/tough/0.24.0/tough/ | Select for TUF repository loading, root-chain verification, expiration enforcement, metadata limits, persistent datastore, and target hash/length verification. Its documented lack of delegated roles/TAP 3/TAP 4 is acceptable for one bounded targets role in the initial release and must remain an explicit scope limit. |
| Bounded HTTPS metadata and asset transport | `ureq` | `3.4.0` | https://docs.rs/ureq/3.4.0/ureq/ | Select its blocking API with explicit global, resolve, connect, response, and body timeouts and an allowlisted HTTPS origin; configure certificate verification deliberately and never follow an unallowlisted redirect. |
| Windows archive extraction | `zip` | `8.6.0` | https://docs.rs/zip/8.6.0/zip/read/struct.ZipFile.html | Select only with enclosed_name/path-component checks, entry-count/expanded-size limits, symlink/reparse-point rejection, and extraction into a private staging directory; the library warning about unsafe names remains part of the implementation acceptance criteria. |
| Linux archive extraction | `tar plus flate2` | `tar 0.4.46; flate2 1.1.9` | https://docs.rs/tar/0.4.46/tar/ and https://docs.rs/flate2/1.1.9/flate2/ | Select tar.gz with bounded streaming extraction, explicit entry/path/symlink checks, and a private staging directory; tar's documented best-effort traversal protection is not treated as sufficient against concurrent destination mutation. |
| Cross-platform startup-check coordination | `fs4` | `1.1.0` | https://docs.rs/fs4/1.1.0/fs4/ | Select synchronous advisory file locks for one user-scoped check/activation coordinator; use atomic state replacement and platform-specific activation rules because an advisory lock is coordination, not authorization or crash proof. |

## Blockers

### `B-M4-M6-NATIVE-ACCEPTANCE`

- Status: `blocked`
- Description: The initial Windows 10 22H2 x64 and Linux x86_64-unknown-linux-gnu with glibc 2.31+ targets are design proposals; native installer, locked-binary, runtime-floor, rollback, and uninstall acceptance remain future M4/M6 work and do not block the completed M0 design.
- Unblocks: `M4-T3`, `M6-T2`

### `B-M5-TRUST-SETUP`

- Status: `blocked`
- Description: The trust design is complete, but generating offline keys, storing signing material, configuring GitHub environments, and publishing the bootstrap root require a maintainer with credentials; no such setup was performed here.
- Unblocks: `M5-T2`, `M5-T3`

### `B-M6-NATIVE-HOSTS`

- Status: `blocked`
- Description: Install, update, rollback, locked-binary, uninstall, and concurrent-session acceptance require a native Windows x64 machine and a native Linux x64 workstation; this roadmap task has not performed those tests.
- Unblocks: `M6-T2`, `M6-T3`

## Operating rules

- Each future session reads this JSON and distribution-handoff.md before selecting work.
- Each future session reconciles branch, HEAD, upstream, staged and unstaged changes before selecting work.
- Each future session executes the first ready task whose dependencies are complete.
- After work, update task status and evidence in this JSON, regenerate distribution-roadmap.md with the repository validator, and update distribution-handoff.md.
- Record blockers narrowly and continue independent useful work where dependencies permit.
- Never mark a task completed from a plan, compilation, another agent claim, or unsupported assertion; completion requires the task's stated evidence.
- Keep public release publication a separate explicit action; do not publish a release merely because roadmap tasks are complete.

## Milestones

### M0 — Product contract and installation/update design

- Status: `completed`
- Objective: Freeze the user-visible startup, installation, coexistence, trust, platform, and state-machine contract before implementation.

#### M0-T1 — Contract and startup state machine

- Status: `completed`
- Dependencies: none
- Objective: Define the startup decision table and state transitions for default update checks, version-change and unresolved-state rechecks, explicit consent, activation, fallback, and session outcomes.
- User-visible outcome: Users get predictable default update checks without automatic installation: they can Install, Continue this time, or Skip this release, while Codex starts normally with ordinary approval fallback whenever updating or automatic approval is unavailable.

**Expected implementation areas**

- `src/main.rs` (`existing`): Preserve the current command dispatch boundary and keep updater work outside the hook process.
- `src/launcher.rs` (`existing`): Map the current run, diagnose, and verification lifecycle before adding a wrapper startup state machine.
- `docs/product-contract.md` (`existing`): Extend the normative wrapper, fallback, consent, and noninteractive behavior contract.
- `docs/architecture.md` (`existing`): Record transitions, ownership boundaries, and no-replay/no-restart-after-Codex-start rules.

**Deliverables**

- The structured startup_decision_table in this roadmap: checks are enabled by default; a changed Codex version and unresolved compatibility state trigger a bounded check before the installed implementation is attempted; disabled checks, backoff, no applicable release, unavailable service, declined installation, and Skip this release continue with the installed policy.
- The structured startup_state_transitions in this roadmap: Install is explicit and completes before Codex starts; Continue this time and Skip this release do not install; noninteractive sessions never prompt or consume Codex input; failed activation uses the known-good payload; and a started session is never replayed or restarted.
- A fixed local outcome taxonomy separating capability success, genuine hook success, no hook invocation, hook incompatibility, and command execution failure; successful Codex exit alone cannot establish hook compatibility or project-wide verified support.
- A rule that no startup updater check or prompt runs in the hook protocol process or writes hook stdout, and that normal arguments, cwd, terminal I/O, ordinary approval fallback, and child exit status are preserved.

**Validation**

- Review the decision table and transitions against the existing run and hook call paths in src/main.rs, src/launcher.rs, src/hook.rs, and src/broker/ at inspected source commit 296008527103e98b9d9f9f20fe6d4e8508346b21.
- Validate the canonical JSON and generated Markdown with cargo run --bin validate_distribution_roadmap -- --write and --check; defer executable table-driven behavior tests to M2/M3/M6 rather than making future implementation tests a design completion condition.

**Completion evidence**

- docs/distribution-roadmap.json revision 2 contains the concrete startup_decision_table and startup_state_transitions, and docs/distribution-roadmap.md is regenerated from them.
- The design was reviewed against existing src/main.rs, src/launcher.rs, src/hook.rs, src/broker/, docs/product-contract.md, and docs/architecture.md without changing runtime authorization behavior.
- The roadmap validator write/check commands and git diff --check pass for this design change.

**Risks and unresolved decisions**

- The implementation must keep the bounded startup check outside the hook process and must not let a slow or unavailable service delay Codex beyond its fixed budget.
- The exact startup issue mentioned in supplied 0.154.0 evidence is unknown and is not evidence for this roadmap.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M0-T2 — Platform, package, path, and coexistence contract

- Status: `completed`
- Dependencies: `M0-T1`
- Objective: Select the initial Windows x64 and Linux x64 package/runtime targets from the current Cargo and CI constraints, define user-scoped paths and stable-launcher/versioned-payload ownership, and document explicit coexistence and migration for Cargo or package-manager installations.
- User-visible outcome: Users can tell exactly which native targets are supported, where files are owned, how codexa is found, and what happens when an existing Cargo-managed installation is present.

**Expected implementation areas**

- `Cargo.toml` (`existing`): Ground the package name, current binary layout, target-specific dependencies, and future release binaries.
- `src/codex.rs` (`existing`): Preserve actual Codex executable resolution and avoid recursive self-resolution or command shadowing.
- `README.md` (`existing`): Document supported native targets, user-scoped installation paths, PATH behavior, and Cargo coexistence.
- `src/update/paths.rs` (`planned`): Centralize user-scoped version, staging, active, state, cache, and rollback paths without machine-private assumptions.

**Deliverables**

- The structured initial_support_targets decision selects x86_64-pc-windows-msvc with a proposed Windows 10 22H2 (build 19045) floor and x86_64-unknown-linux-gnu with a proposed glibc 2.31+ floor; musl, other libc families, other architectures, macOS, WSL, containers, and IDE/remote surfaces remain outside the initial target.
- The structured installation_ownership decision assigns user-scoped Windows %LOCALAPPDATA% and Linux XDG data/state/cache locations for codexa, immutable versions/<release>, staging, cache, state/active.json, rollback, and logs; no administrator privilege or Codex user-data ownership is required.
- The stable launcher reads an atomically replaced active pointer and starts immutable versioned payloads, so a running Windows executable is never replaced; the same ownership rule applies on Linux and old payloads remain available for explicit rollback until no active session uses them.
- The documented entry point is codexa or codex-autoapprover run; direct codex is never shadowed or replaced. Existing Cargo/package-manager installations remain usable, are detected by ownership/path, are never overwritten, and receive an explicit migration offer or instructions rather than silent adoption.

**Validation**

- Review Cargo.toml target-specific dependencies and .github/workflows/ci.yml: current Windows and ubuntu-latest jobs establish build/test coverage only, not the proposed runtime floors.
- Review src/codex.rs and the existing launcher boundary for recursive self-resolution, preserved arguments/cwd/stdio/exit status, and no codex command shadowing.
- Record spaced/non-ASCII paths, PATH/profile changes, Cargo-managed coexistence, locked binaries, and runtime-floor checks as M4-T3/M6-T2 acceptance work; their absence does not block this design completion.

**Completion evidence**

- docs/distribution-roadmap.json revision 2 contains the concrete initial_support_targets and installation_ownership maps, including proposed-versus-validated status and exact entry-point/coexistence rules.
- Cargo.toml, .github/workflows/ci.yml, src/codex.rs, and the existing launcher/docs were inspected; no claim is made that current CI or existing live verification validates the proposed installable runtime floors.
- Native acceptance is explicitly retained under M4-T3 and M6-T2, while the M0 design decision is complete.

**Risks and unresolved decisions**

- The proposed Windows and glibc floors must be validated by oldest-target builds and native acceptance before any public support claim; current ubuntu-latest/windows-latest CI is insufficient evidence.
- A later implementation must preserve user-owned Codex configuration and distinguish an autoapprover-owned path from Cargo/package-manager ownership before offering migration.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M0-T3 — Release trust, bootstrap, and maintained-library decision

- Status: `completed`
- Dependencies: `M0-T1`
- Objective: Choose a concrete authenticated release trust model and maintained libraries after reviewing primary documentation; define bootstrap trust, expiration/replay handling, key rotation/revocation, explicit rollback, and the future maintainer setup without creating secrets or weakening runtime authorization.
- User-visible outcome: Users can understand what authenticates an update, how an initial trust anchor is installed, how keys rotate, and why an untrusted update is never activated.

**Expected implementation areas**

- `Cargo.toml` (`existing`): Record only reviewed, maintained dependencies when the trust and transport design is approved.
- `src/compatibility.rs` (`existing`): Keep release metadata eligibility separate from runtime hook authorization and reviewed compatibility.
- `docs/threat-model.md` (`existing`): Extend the supply-chain, bootstrap, signing, downgrade, and key-rotation threat model.
- `src/update/verify.rs` (`planned`): Implement authenticated metadata and asset verification only after the library and trust decision.

**Deliverables**

- The structured release_trust_model selects TUF 1.0 metadata with a pinned root, 2-of-3 offline root and targets thresholds, bounded HTTPS origin/redirect policy, exact target hashes and lengths, safe expiry, monotonic metadata versions, explicit key rotation/revocation, and explicit local rollback only.
- Bootstrap trust is documented as a user-visible boundary: the initial installer/wrapper comes from the documented GitHub HTTPS origin and carries the reviewed public root; a checksum fetched beside a binary is never treated as independent publisher authentication.
- The structured release_library_review records primary documentation and decisions for tough 0.24.0, ureq 3.4.0, zip 8.6.0, tar 0.4.46, flate2 1.1.9, and fs4 1.1.0. No new dependency or cryptographic key is added by this design change.
- Metadata may select an asset but can never authorize a hook, modify the compatibility registry, bypass process/session/cwd/schema/tool/exact-command checks, or override fail-closed broker behavior.
- Future maintainer actions are explicit: choose owners, generate and protect offline keys, configure least-privilege GitHub signing/release environments, record fingerprints, perform a rotation/revocation drill, and publish the bootstrap root only after M5/M6 review.

**Validation**

- Review the trust decision against docs/threat-model.md and the existing compatibility/broker boundary for compromised origin, stale metadata, key compromise, redirect abuse, downgrade, interrupted activation, and metadata/runtime authorization separation.
- Consult the primary crate documentation recorded in release_library_review and preserve each documented limitation as an implementation acceptance condition; negative fixtures remain under M1/M3/M6.

**Completion evidence**

- docs/distribution-roadmap.json revision 2 contains the concrete release_trust_model, maintainer action list, and release_library_review with observed documentation versions and URLs.
- Primary documentation consulted: https://docs.rs/tough/0.24.0/tough/, https://docs.rs/ureq/3.4.0/ureq/, https://docs.rs/zip/8.6.0/zip/read/struct.ZipFile.html, https://docs.rs/tar/0.4.46/tar/, https://docs.rs/flate2/1.1.9/flate2/, and https://docs.rs/fs4/1.1.0/fs4/.
- No keys, signing secrets, GitHub settings, dependency changes, release assets, or persistent configuration were created or changed.

**Risks and unresolved decisions**

- Tough 0.24.0 documents no delegated roles/TAP 3/TAP 4; the initial design therefore uses one bounded targets role and must not imply broader TUF feature coverage.
- The initial installer still has a bootstrap trust boundary that requires a maintainer-selected publication process; until M5/M6 complete, no public release or support claim is authorized.
- The implementation must re-audit current crate versions and APIs when dependencies are added; observed documentation versions are design evidence, not a lockfile or release claim.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

### M1 — Compatibility manifest and release selection

- Status: `in_progress`
- Objective: Define bounded, authenticated, deterministic release metadata and keep release applicability separate from hook authorization.

#### M1-T1 — Versioned release manifest schema

- Status: `completed`
- Dependencies: `M0-T2`, `M0-T3`
- Objective: Define and strictly validate machine-readable release metadata containing release version, supported assets, OS/architecture/runtime requirements, hashes, provenance, release notes, and compatibility information.
- User-visible outcome: The updater can reject malformed, incomplete, prerelease, unsigned, incompatible, or downgrade metadata before any download or activation.

**Expected implementation areas**

- `src/compatibility.rs` (`existing`): Reuse exact platform/surface/protocol/tool compatibility concepts without conflating release selection with verified support.
- `src/update/manifest.rs` (`existing`): Implement bounded schema parsing, strict nested validation, deterministic serialization, synthetic fixtures, and the crate-private TUF verification seam.
- `docs/compatibility.md` (`existing`): Document exact reviewed tuples, experimental eligibility, exclusions, and the boundary between evidence and metadata.

**Deliverables**

- A versioned manifest schema with bounded sizes, required fields, canonical serialization rules, and explicit schema evolution policy.
- Asset records for OS, architecture, runtime/libc, package format, download origin, size bound, digest, provenance, and release notes URL; TUF authenticates the manifest target and its hash/length without a competing manifest signature format.
- Compatibility records for exact reviewed tuples, experimental eligibility, exclusions, hook protocol, tool schema, and response behavior.

**Validation**

- Focused unit tests cover synthetic valid metadata, nested unknown fields, duplicate JSON keys, duplicate assets, contradictory compatibility identities, oversized input, unsupported schema versions, malformed stable versions, prereleases, invalid hashes and lengths, unsupported hook/tool schemas, inconsistent runtime/archive pairs, canonical ordering, and the TUF proof boundary.
- The typed parser has no path to arming state or broker authorization; the descriptive manifest remains separate from src/compatibility.rs and runtime decision checks.
- The repository test and lint gates run on the native Windows checkout; native Linux execution remains CI evidence for a later pushed commit.

**Completion evidence**

- src/update/manifest.rs implements schema version 1 with bounded parsing, strict nested fields, duplicate-key rejection, duplicate identity checks, stable-version/hash/length/runtime validation, deterministic serialization, and a crate-private TUF-verified-target adapter.
- tests/fixtures/distribution_manifest/valid.json is a synthetic three-status manifest; duplicate-key.json and unknown-field.json plus focused mutations exercise rejected inputs. Fixtures contain no production trust anchors or live evidence.
- docs/compatibility.md records the manifest field contract, proposed runtime-floor boundary, deterministic serialization, and TUF authentication boundary without changing the reviewed Windows 0.153.2/0.154.0 or Linux 0.151.0 registry entries.
- cargo fmt --check, cargo test --all-targets, cargo clippy --all-targets --all-features -- -D warnings, and cargo build --all-targets passed in this checkout after the implementation.
- cargo run --bin validate_distribution_roadmap -- --write and --check, plus git diff --check, passed after roadmap regeneration.

**Risks and unresolved decisions**

- Schema version 1 uses snake_case field names and kebab-case enum values; future schema changes require an explicit versioned decoder or migration rather than permissive fallback.
- TUF verification remains a later integration task: this parser accepts no signatures and parsing never produces an authenticity status. The future adapter must authenticate the exact target bytes and TUF target length/hash before exposing trusted metadata.
- A release asset may be applicable while its Codex compatibility remains experimental; later selection and UI work must show both facts.
- Proposed Windows 10 22H2 and Linux glibc 2.31 runtime floors remain unvalidated until native M4/M6 acceptance.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M1-T2 — Deterministic applicable-release selection

- Status: `completed`
- Dependencies: `M0-T2`, `M1-T1`
- Objective: Select the newest applicable stable release, not merely the newest overall release, using bounded metadata and explicit platform/runtime rules.
- User-visible outcome: Users are offered only a release that matches the current wrapper target, architecture, runtime, install channel, and downgrade policy.

**Expected implementation areas**

- `src/codex.rs` (`existing`): Supply actual installed Codex executable and version detection to the selection input.
- `src/update/selection.rs` (`existing`): Implement pure deterministic numeric release selection over TUF-authenticated manifests and typed platform/runtime/policy inputs.
- `src/launcher.rs` (`existing`): Invoke selection before Codex starts while preserving current arguments, cwd, I/O, and policy gates.

**Deliverables**

- A pure selector that consumes TUF-authenticated manifests and explicit installed-version, Codex, platform, architecture, runtime, surface, and compatibility-policy inputs.
- Numeric release ordering across every supplied candidate, with newer-inapplicable versus older-applicable behavior, prerelease filtering at manifest/input parsing, unsupported-target/runtime handling, same-version responses, and downgrade refusal.
- A typed outcome with fixed-category candidate/catalog rejection reasons, reviewed versus experimental classification, and a user-facing applicability explanation containing current/new versions, compatibility status, and release-notes metadata.

**Validation**

- Focused selector tests cover Windows and Linux candidates, numeric 0.9.0 versus 0.10.0 ordering, newer-incompatible/older-applicable candidates, reviewed versus experimental automatic/strict policy, exact exclusions, runtime floors and unknown runtime, duplicate/conflicting records, equal-ranked assets, input permutations, empty/current/downgrade catalogs, malformed Codex versions, and read-only hook-registry behavior.
- Selection requires the TUF-authenticated manifest wrapper, never treats a hash/length match alone as publisher authentication, and cannot download, execute, install, activate, or authorize a hook.
- The selected result preserves an experimental classification; automatic mode chooses the newest applicable release, while strict mode chooses the newest exact-reviewed applicable release.

**Completion evidence**

- src/update/selection.rs implements the pure selector, typed runtime floors for Windows 10/11-style Hx requirements and Linux glibc requirements, numeric StableVersion ordering, fixed-category outcomes, ambiguity rejection, and applicability explanations.
- Focused selector tests pass for the synthetic valid manifest and cover Windows/Linux, numeric ordering, incompatible latest release, policy classification, exact exclusions, runtime boundaries, ambiguity, permutation invariance, no downgrade/current release, malformed Codex versions, and unchanged compatibility-registry length.
- docs/compatibility.md documents the explicit M1-T2 decision: automatic mode selects the newest applicable reviewed or explicitly experimental release; strict mode selects the newest applicable exact-reviewed release; exact exclusions and ambiguity fail closed.
- cargo fmt --check, cargo test --all-targets, cargo clippy --all-targets --all-features -- -D warnings, and cargo build --all-targets passed in the native Windows checkout.
- cargo run --bin validate_distribution_roadmap -- --write and --check, plus git diff --check, passed after roadmap regeneration.

**Risks and unresolved decisions**

- Selection is deliberately not wired into startup, network, state, consent, installation, rollback, or release publication; those remain later milestones.
- The typed runtime model covers the proposed initial native Windows x64 and Linux x64/glibc targets only. Native installer/runtime-floor acceptance remains a later M4/M6 blocker.
- TUF authentication and selection remain separate from hook authorization; a selected release still cannot change the existing compatibility registry or broker checks.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M1-T3 — Compatibility and authorization boundary

- Status: `planned`
- Dependencies: `M1-T1`, `M1-T2`
- Objective: Specify how installed release metadata, local observations, reviewed support, experimental eligibility, and runtime hook authorization remain distinct.
- User-visible outcome: A newer installed wrapper or locally successful session never silently becomes project-wide reviewed support or weakens broker checks.

**Expected implementation areas**

- `src/compatibility.rs` (`existing`): Extend typed status and tuple metadata without converting local success into Verified automatically.
- `src/decision.rs` (`existing`): Preserve exact request/schema/command decisions independent of release metadata.
- `src/broker/` (`existing`): Retain Windows and Linux identity, ancestry, session, cwd, schema, and tool authorization checks.
- `docs/compatibility.md` (`existing`): Record reviewed evidence separately from experimental runtime observations.

**Deliverables**

- A compatibility status model for reviewed, experimental, candidate, incompatible, and unknown states.
- A decision table showing metadata selection never authorizes a request and local success never promotes a registry tuple.
- Explicit downgrade, exclusion, schema, and unsupported-surface behavior.

**Validation**

- Regression tests for strict mode, automatic mode, exact reviewed entries, experimental entries, exclusions, and forged metadata.
- Review that no updater path runs inside hook protocol execution or emits on hook stdout.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The release manifest may describe compatibility claims but cannot be the source of truth for reviewed support without a separate maintainer review.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `false`

### M2 — Startup check and persistent state

- Status: `planned`
- Objective: Implement bounded startup checks, atomic user-scoped state, version-change detection, unresolved-state rechecks, backoff, coordination, and compatibility outcome propagation.

#### M2-T1 — Atomic state and concurrent-check coordination

- Status: `planned`
- Dependencies: `M0-T2`, `M1-T1`
- Objective: Define and implement user-scoped state for installed version, last successful check, validators, skip scope, backoff, failure category, and active update coordination.
- User-visible outcome: Concurrent wrapper launches do not duplicate downloads/prompts, corrupt state, or expose secrets, and a crash leaves recoverable state.

**Expected implementation areas**

- `src/launcher.rs` (`existing`): Provide the wrapper startup boundary and preserve current child lifecycle behavior.
- `src/update/state.rs` (`planned`): Implement atomic user-scoped state, bounded records, lock/coordination, and crash recovery.
- `docs/threat-model.md` (`existing`): Document state privacy, symlink/path risks, concurrent launch behavior, and recovery.

**Deliverables**

- A versioned state schema containing only minimal install/check/version/failure metadata.
- Atomic write and lock/coordination behavior for concurrent wrappers and interrupted writes.
- Retention and cleanup rules that never store commands, hook payloads, credentials, session secrets, or unnecessary machine identifiers.

**Validation**

- Deterministic tests for concurrent readers/writers, truncated state, stale locks, interrupted replace, symlink/path rejection, and bounded record sizes.
- Verify user configuration and Codex data are never treated as updater state.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Windows and Linux atomic replacement/locking semantics differ and need platform-specific implementation and tests.
- The lock must coordinate checks without holding a lock across consent or a long download.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `false`

#### M2-T2 — Bounded startup check and unresolved-state policy

- Status: `planned`
- Dependencies: `M1-T2`, `M2-T1`
- Objective: Check for an applicable release when Codex version changes and on subsequent wrapper launches while compatibility is unresolved, subject to validators, timeout, backoff, and noninteractive rules.
- User-visible outcome: The wrapper remains usable during service failure or timeout, checks unresolved compatibility on later launches, and never blocks a noninteractive Codex session on an update prompt.

**Expected implementation areas**

- `src/codex.rs` (`existing`): Detect the actual installed executable and version at startup.
- `src/update/check.rs` (`planned`): Implement bounded transport, cache validators, version-change detection, server backoff, and applicability checks.
- `src/cli.rs` (`existing`): Add explicit update, update --check, diagnose, rollback, and disable-startup-check controls without consuming Codex prompt input.

**Deliverables**

- A startup check policy for version change, unresolved compatibility, no applicable release, declined update, skipped release, timeout, unavailable GitHub, and server-directed backoff.
- A network budget and cache validator policy that continues with the installed wrapper on all check failures.
- A noninteractive policy that suppresses prompts and does not read Codex prompt input.

**Validation**

- Mock transport and deterministic clock tests for validators, timeout, 5xx, unavailable service, Retry-After/backoff, version change, unresolved recheck, and concurrent coordination.
- Assert no updater code path is reachable from src/hook.rs or the broker request process.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The check origin and redirect policy depend on the trust design and must not be replaced by arbitrary URLs.
- Startup latency must be bounded tightly enough that normal Codex launch remains predictable.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M2-T3 — Compatibility outcome propagation and local diagnostics

- Status: `planned`
- Dependencies: `M1-T3`, `M2-T1`
- Objective: Propagate hook outcomes to the wrapper with fixed categories that distinguish no invocation, successful exchange, compatibility failure, and command execution failure.
- User-visible outcome: A successful Codex exit alone never marks compatibility as working, a hook failure falls back to ordinary approval, and diagnosis explains the local outcome without leaking sensitive data.

**Expected implementation areas**

- `src/audit.rs` (`existing`): Extend fixed-category redacted local diagnostics while preserving separate entry, validated-request, decision, and emission stages.
- `src/launcher.rs` (`existing`): Consume bounded child/broker outcomes and preserve ordinary Codex fallback and exit status.
- `src/hook.rs` (`existing`): Keep protocol stdout exact and report no decision on incompatible or failed requests.
- `src/update/outcome.rs` (`planned`): Define a bounded wrapper-facing result type for local compatibility state.

**Deliverables**

- Fixed categories for no hook invocation, successful hook exchange, compatibility rejection/failure, and command execution failure.
- A bounded propagation mechanism that cannot carry commands, payloads, credentials, session secrets, or arbitrary child output into update state.
- Diagnose output and state records that distinguish local observation from reviewed verification.

**Validation**

- Tests for no request plus successful child, successful request plus failed command, hook no-decision, hook transport failure, and normal approval fallback.
- Verify a failed hook never restarts or replays a Codex session or command.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The current launcher observes child lifecycle but does not yet define an updater outcome channel; the channel must avoid coupling the hook protocol to startup update logic.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `false`

### M3 — Consent and update installation

- Status: `planned`
- Objective: Offer consent safely, authenticate and stage updates, activate atomically, roll back on failure, and restart only the wrapper before Codex starts.

#### M3-T1 — Consent and explicit update commands

- Status: `planned`
- Dependencies: `M0-T1`, `M1-T2`, `M2-T2`
- Objective: Define interactive Install, Continue this time, and Skip this release behavior plus explicit update, update --check, diagnose, rollback, and startup-check disable controls.
- User-visible outcome: Users see current/new versions, compatibility status, and release notes, can decline without disruption, and can later reconsider a skipped release after a Codex version change.

**Expected implementation areas**

- `src/cli.rs` (`existing`): Add explicit updater subcommands and options without changing the Codex argument separator semantics.
- `src/launcher.rs` (`existing`): Keep consent before Codex starts and preserve normal launch when consent is declined.
- `docs/product-contract.md` (`existing`): Specify consent, skip scope, noninteractive behavior, and explicit disable semantics.

**Deliverables**

- Interactive decision UI with Install, Continue this time, and Skip this release.
- Skip scope and re-consideration rules tied to release/Codex-version state rather than an irreversible global suppression.
- Explicit command behavior and exit/status output for update, update --check, diagnose, rollback, and disable-startup-check.

**Validation**

- Interactive and noninteractive tests prove no updater prompt consumes Codex input.
- Tests cover decline, skip, later Codex version change, explicit update, disabled checks, and no applicable update.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Consent wording must expose compatibility status and release notes without implying that an update is reviewed hook support.
- The update command must not accidentally enter the hook protocol path.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `true`

#### M3-T2 — Authenticated staging, activation, and rollback

- Status: `planned`
- Dependencies: `M0-T3`, `M1-T1`, `M3-T1`
- Objective: Install immutable versioned payloads into user-scoped staging, verify metadata/assets, activate atomically, and recover from interrupted or unhealthy candidates.
- User-visible outcome: A bad, incomplete, tampered, interrupted, or incompatible download cannot replace the working wrapper, and rollback is explicit and recoverable.

**Expected implementation areas**

- `src/update/install.rs` (`planned`): Implement bounded download, constrained extraction, integrity/authentication checks, health check, activation, rollback, and retention.
- `src/update/paths.rs` (`planned`): Provide immutable version directories, staging paths, active pointer/launcher, and user-scoped ownership.
- `docs/threat-model.md` (`existing`): Record origin, redirect, archive traversal, locking, activation, rollback, and retention threats.

**Deliverables**

- Constrained download origins and redirects, bounded download/extraction sizes, safe archive-entry validation, and staging outside the active payload.
- Authenticated metadata and asset integrity verification before activation.
- Atomic activation, candidate health check, rollback, interrupted-install recovery, retention, and active-session version protection.
- Windows locked-binary strategy using a stable launcher plus immutable versioned payloads or a justified equivalent.

**Validation**

- Mock and filesystem tests for invalid signature/hash, path traversal, absolute/symlink archive entries, truncated download, interrupted extraction, locked binary, failed health check, rollback, and retention.
- Prove no active Codex session is restarted, replayed, or affected by an update.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The activation mechanism must work when the currently running wrapper executable is locked by Windows.
- Archive formats and supported package shapes are not selected until M0 platform/package design and M5 packaging are complete.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `false`

#### M3-T3 — Wrapper-only restart and loop prevention

- Status: `planned`
- Dependencies: `M2-T3`, `M3-T2`
- Objective: After accepted activation, restart only the wrapper before Codex starts, preserve arguments/cwd/stdio/exit status, and prevent update/restart loops.
- User-visible outcome: An accepted update takes effect on the next wrapper-owned launch without replaying a started Codex session or changing the user command.

**Expected implementation areas**

- `src/launcher.rs` (`existing`): Preserve current child command construction, inherited I/O, cwd, arguments, and exit propagation.
- `src/codex.rs` (`existing`): Keep official executable detection separate from wrapper update activation.
- `src/update/restart.rs` (`planned`): Implement one-time restart handoff, loop marker/limit, and pre-Codex-only restart.

**Deliverables**

- A restart contract that executes only before Codex starts and preserves command-line arguments, cwd, stdin/stdout/stderr, and final exit status.
- Loop prevention and interrupted-restart recovery.
- A hard rule that hook failure during an already-started session never triggers restart or replay.

**Validation**

- Tests for accepted update, declined update, failed activation, restart marker reuse, argument quoting, cwd, stdio, exit status, and Codex already started.
- Windows locked-binary and concurrent-session tests once native hosts are available.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Restarting through a stable launcher must not create recursive self-resolution or accidentally invoke the original codex binary as the wrapper.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `false`

### M4 — Native installers and uninstall

- Status: `planned`
- Objective: Provide user-scoped, idempotent native Windows and Linux installation/uninstallation with an explicit codexa entry point and safe coexistence.

#### M4-T1 — User-scoped installers and entry point

- Status: `planned`
- Dependencies: `M0-T2`, `M3-T2`
- Objective: Implement Windows PowerShell and Linux shell installers that install a prebuilt native package without Rust, Cargo, Git, or administrator privileges.
- User-visible outcome: A supported user can install and invoke codexa or codex-autoapprover run from a documented user-scoped path without replacing codex.

**Expected implementation areas**

- `install.ps1` (`planned`): Provide the Windows user-scoped bootstrap with explicit origin/trust messaging and idempotent PATH/profile handling.
- `install.sh` (`planned`): Provide the Linux user-scoped bootstrap with explicit origin/trust messaging and idempotent PATH/profile handling.
- `src/bin/codexa.rs` (`planned`): Provide the documented wrapper entry point without shadowing the official codex command.
- `README.md` (`existing`): Document supported targets, bootstrap trust, exact install commands, PATH behavior, and no-placeholder policy.

**Deliverables**

- Native Windows x64 and Linux x64 installer flows with user-scoped paths and explicit supported-runtime checks.
- Idempotent installation, profile/PATH behavior, spaced/non-ASCII path handling, and codexa/codex-autoapprover run entry point.
- Bootstrap trust warning and a rule that public instructions never contain placeholder download commands presented as working.

**Validation**

- Run installers in isolated user directories without admin privileges, Rust, Cargo, or Git.
- Test repeat installation, spaced/non-ASCII paths, PATH/profile outcomes, and direct original codex invocation remaining unchanged.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The first bootstrap may require a trusted package source or signed installer; its trust boundary must be explicit.
- Shell/profile modification behavior differs across Linux shells and must remain opt-in and reversible.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `true`
- Human action: `false`

#### M4-T2 — Existing-install migration and uninstall

- Status: `planned`
- Dependencies: `M0-T2`, `M3-T2`, `M4-T1`
- Objective: Detect Cargo/package-manager installations, offer migration without overwriting them, and uninstall only owned files and configuration edits.
- User-visible outcome: Users can keep or explicitly migrate an existing installation, and uninstall preserves Codex configuration, authentication, user data, and unrelated PATH/profile content.

**Expected implementation areas**

- `src/update/paths.rs` (`planned`): Track owned paths and install channel without treating arbitrary files as owned.
- `src/update/install.rs` (`planned`): Implement explicit migration/ownership checks and removal manifests.
- `docs/product-contract.md` (`existing`): Specify no-overwrite, migration consent, uninstall scope, and preservation rules.

**Deliverables**

- Installation-channel detection and explicit migration offer/instructions for Cargo/package-manager installs.
- An ownership manifest for files and profile edits created by the installer.
- Uninstall behavior that removes only owned files and edits and leaves Codex configuration, authentication, user data, and unrelated hooks intact.

**Validation**

- Fixtures for Cargo-managed, package-manager, and installable-package layouts.
- Uninstall tests with unrelated files, existing hooks, Codex config, non-ASCII paths, and partial installation state.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Ownership cannot be inferred safely from path alone; migration and uninstall need explicit markers.
- A user may have multiple wrappers or package-manager installations; diagnostics must show the selected executable and channel.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `true`

#### M4-T3 — Native installation acceptance

- Status: `planned`
- Dependencies: `M0-T2`, `M4-T1`, `M4-T2`
- Objective: Prove the supported package and installer behavior on the selected native Windows x64 and Linux x64 targets.
- User-visible outcome: Release documentation names tested targets and limitations instead of implying universal Windows/Linux support.

**Expected implementation areas**

- `.github/workflows/ci.yml` (`existing`): Extend existing Windows/Linux CI with packaging/install smoke coverage where appropriate.
- `docs/compatibility.md` (`existing`): Record tested installation/runtime scope separately from Codex hook compatibility.
- `tests/` (`existing`): Add deterministic installer/path/ownership fixtures without requiring live Codex.

**Deliverables**

- A native acceptance matrix for clean install, repeat install, migration, update, rollback, uninstall, PATH, spaced/non-ASCII paths, and no-admin operation.
- Documented Linux libc/minimum-runtime and Windows minimum-runtime results.
- A list of unsupported platforms/architectures/runtime environments.

**Validation**

- Native Windows x64 laptop run and native Linux x64 workstation run in isolated user directories.
- Record exact package, host/runtime, installer, update, rollback, and uninstall results without raw credentials or machine-private identifiers.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- This cannot be completed from the current Windows planning environment alone.
- A CI runner result is not a substitute for interactive installer and locked-binary acceptance on the native machines.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `true`
- Human action: `true`

### M5 — Release automation

- Status: `planned`
- Objective: Build, test, package, authenticate, and publish complete native release assets with least-privilege provenance and a maintainer procedure.

#### M5-T1 — Native build and package workflows

- Status: `planned`
- Dependencies: `M1-T1`, `M3-T2`, `M4-T1`
- Objective: Extend CI/release workflows to produce tested Windows x64 and Linux x64 packages with stable versioning and explicit asset names.
- User-visible outcome: A release contains identifiable, reproducible native assets rather than an ad hoc CI artifact.

**Expected implementation areas**

- `.github/workflows/ci.yml` (`existing`): Preserve current Linux/Windows format, test, Clippy, build, diagnose, and diff gates.
- `.github/workflows/release.yml` (`planned`): Build native packages, run release gates, and publish only complete candidate assets.
- `Cargo.toml` (`existing`): Ground package versioning and binary targets in the existing Rust package.

**Deliverables**

- Stable release versioning and explicit asset naming for Windows x64 and Linux x64 runtime targets.
- Build/test/package jobs with reproducible inputs and retained provenance.
- A workflow rule that no release becomes discoverable until the complete asset set is available.

**Validation**

- CI checks for format, tests, Clippy warnings denied, build, diagnose, packaging, and artifact inspection.
- Verify workflow permissions are least-privilege and no signing secret appears in logs.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- The Linux target matrix depends on the libc/minimum-runtime decision from M0.
- A CI artifact, draft release, prerelease, and stable public release must remain distinct states.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `true`
- Human action: `true`

#### M5-T2 — Authenticated metadata and provenance

- Status: `planned`
- Dependencies: `M0-T3`, `M1-T1`, `M5-T1`
- Objective: Generate signed/bounded release metadata, asset hashes, provenance, release notes, and rotation-ready trust records.
- User-visible outcome: The updater can verify what it downloads and users can inspect where a release came from before consenting.

**Expected implementation areas**

- `.github/workflows/release.yml` (`planned`): Generate metadata and provenance using protected signing secrets with least privilege.
- `src/update/verify.rs` (`planned`): Verify metadata, hashes, signatures, provenance, origin, and downgrade policy.
- `docs/threat-model.md` (`existing`): Document signing-secret handling, bootstrap trust, key rotation, and compromise response.

**Deliverables**

- Authenticated manifest generation tied to exact assets, hashes, version, runtime, provenance, and release notes.
- Key rotation and revocation procedure with no silent trust reset.
- Release visibility rules distinguishing draft, prerelease, stable, and incomplete asset sets.

**Validation**

- Verify generated metadata with the updater verifier and reject altered metadata/assets.
- Review workflow permissions, secret exposure, provenance links, and incomplete-release behavior.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Signing bootstrap and key custody require human maintainer action and should not be inferred from GitHub release state.
- No public release should be announced until the first stable trust chain is independently reviewed.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `true`
- Human action: `true`

#### M5-T3 — Maintainer release procedure

- Status: `planned`
- Dependencies: `M5-T1`, `M5-T2`
- Objective: Document the exact one-time GitHub setup and repeatable maintainer procedure from version bump through draft, prerelease, stable publication, rollback, and incident response.
- User-visible outcome: A maintainer can publish or withhold a release deliberately, and roadmap completion cannot accidentally publish software.

**Expected implementation areas**

- `docs/release.md` (`planned`): Document setup, release commands, review gates, asset completeness, signing, and rollback.
- `.github/workflows/release.yml` (`planned`): Encode only the approved automation steps and protected permissions.
- `README.md` (`existing`): Link to the release/install contract without presenting unready commands as public installation instructions.

**Deliverables**

- One-time GitHub repository/environment setup checklist.
- Exact maintainer release procedure and release readiness checklist.
- Rollback, compromised-key, yanked-release, and incomplete-asset response procedure.

**Validation**

- Dry-run the procedure against a draft or fixture without publishing a stable release.
- Peer review that roadmap task completion and CI success do not themselves publish a release.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- GitHub access and signing secret setup are external human actions.
- The first public release requires a separate explicit approval after M6.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `true`
- Human action: `true`

### M6 — End-to-end validation and release handoff

- Status: `planned`
- Objective: Validate the installable updater without overclaiming existing hook evidence and prepare a release readiness report plus first-public-release checklist.

#### M6-T1 — Fake Codex and mock release-server matrix

- Status: `planned`
- Dependencies: `M2-T2`, `M2-T3`, `M3-T1`, `M3-T3`
- Objective: Build deterministic tests for known/new Codex versions, hook success/failure/no request, fallback, update selection, consent, transport, trust, backoff, and incomplete releases.
- User-visible outcome: Most updater and compatibility behavior is reproducible in CI without live Codex, GitHub, or network dependence.

**Expected implementation areas**

- `src/bin/fake_codex.rs` (`existing`): Extend the existing fake Codex fixture for startup/version/hook outcomes without changing real authorization.
- `tests/` (`existing`): Add mock transport, deterministic clock, manifest, consent, state, install, rollback, and fallback tests.
- `src/update/` (`planned`): Expose narrow test seams for transport, clock, filesystem, and release selection.

**Deliverables**

- Fake Codex cases for known versions, new versions, successful hook, failed hook, no request, normal approval fallback, and command failure.
- Mock release-server cases for applicable/no update, declined/skipped, unavailable/timeout, backoff, invalid signature/hash, incompatible asset, downgrade, and incomplete release.
- Deterministic concurrency, state recovery, restart-loop, and no-replay coverage.

**Validation**

- cargo fmt --check
- cargo test --all-targets
- cargo clippy --all-targets --all-features -- -D warnings
- cargo build
- cargo run --bin validate_distribution_roadmap -- --check
- git diff --check

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- Current live Windows 0.153.2 and 0.154.0 evidence verifies the existing hook tuple only; it does not verify new updater behavior.
- Tests must not use live GitHub or real user Codex configuration.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `false`
- Human action: `false`

#### M6-T2 — Native install, update, rollback, and uninstall validation

- Status: `planned`
- Dependencies: `M4-T3`, `M5-T3`, `M6-T1`
- Objective: Run the complete isolated user-directory acceptance matrix on native Windows x64 and native Linux x64, including locked binaries and concurrent sessions.
- User-visible outcome: The first release has evidence for the exact supported native targets and documented limitations, not generic platform claims.

**Expected implementation areas**

- `tests/` (`existing`): Keep portable fixtures and assertions for native acceptance results.
- `docs/compatibility.md` (`existing`): Record installation/runtime evidence separately from existing Codex hook verification.
- `docs/release.md` (`planned`): Record exact host procedures and release acceptance evidence.

**Deliverables**

- Native Windows x64 test record covering install, update, consent, locked-binary activation, rollback, concurrent sessions, uninstall, and PATH.
- Native Linux x64 test record covering selected libc/runtime, install, update, rollback, concurrent sessions, uninstall, and PATH.
- A precise list of unsupported targets and any remaining release blockers.

**Validation**

- Use the Windows laptop at this task, not the hook protocol process, for locked-binary and interactive installer checks.
- Use the Linux workstation at this task for selected libc/minimum-runtime and shell installer checks.
- Confirm Codex arguments, cwd, stdio, exit status, user configuration, hook fallback, and no session replay.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- This task cannot be completed from CI alone.
- Existing live verification must be cited as existing evidence and never reused as proof of updater behavior.

**Required access or action**

- Native Windows: `true`
- Native Linux: `true`
- GitHub access: `false`
- Human action: `true`

#### M6-T3 — Release readiness report and first-public-release checklist

- Status: `planned`
- Dependencies: `M5-T3`, `M6-T2`
- Objective: Prepare the final evidence-backed readiness report and explicit approval checklist without publishing, tagging, or installing a release automatically.
- User-visible outcome: A maintainer can see exactly what passed, what remains experimental, what must be approved, and which explicit command publishes the first stable release.

**Expected implementation areas**

- `docs/release.md` (`planned`): Hold the final readiness report, evidence links, supported-target statement, and publication checklist.
- `docs/distribution-handoff.md` (`existing`): Update the next-session handoff with the first ready task, blockers, commands, and evidence.
- `docs/distribution-roadmap.json` (`existing`): Record completed evidence and remaining blockers in the canonical roadmap.

**Deliverables**

- Release readiness report with exact commit, assets, signatures, CI, native host, install, update, rollback, uninstall, fallback, and limitation evidence.
- First-public-release checklist requiring explicit maintainer approval and separate publication action.
- Updated roadmap, generated Markdown, and concise handoff with no secrets or machine-private evidence.

**Validation**

- Run the roadmap validator and synchronization check.
- Review all completed-task evidence against actual artifacts and commands.
- Confirm no release is published merely because the roadmap is complete.

**Completion evidence**

- Not complete; evidence must be recorded before status becomes `completed`.

**Risks and unresolved decisions**

- A readiness report is not a release; publication remains a separate explicit human action.
- Any unresolved native-host, signing, or GitHub blocker must remain visible rather than being marked completed.

**Required access or action**

- Native Windows: `false`
- Native Linux: `false`
- GitHub access: `true`
- Human action: `true`

## Roadmap validation contract

The repository utility validates the canonical JSON and ensures the checked-in Markdown rendering is synchronized; it does not establish release readiness or perform network, install, Codex, or publication actions.

- Unique milestone and task IDs.
- Every dependency references an existing task and the dependency graph has no cycles.
- Statuses are limited to planned, in_progress, blocked, and completed.
- Every task has the required objective, outcome, status, dependencies, implementation areas, deliverables, validation, evidence, risks, and access fields.
- Completed tasks have non-empty completion evidence.
- Current milestone and next executable task references are valid.
- The JSON and generated Markdown render are byte-for-byte synchronized.
- The roadmap contains no detected secrets, credential markers, session-secret environment names, or machine-private paths.
