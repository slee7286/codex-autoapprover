# Distribution roadmap handoff

This is a planning and partial-implementation handoff, not an installer, release approval, or compatibility promotion. The merge into the verified release foundation preserves its exact-certificate admission; an update manifest is not a certificate.

## Current state

- Repository: `slee7286/codex-autoapprover`
- Original roadmap branch: `feat/distribution-roadmap`; this handoff is maintained on `main` after reconciliation.
- Original roadmap inspected source commit: `296008527103e98b9d9f9f20fe6d4e8508346b21`; do not treat that old source as the current runtime policy.
- Roadmap revision: `7`
- Current milestone: `M2 - Startup check and persistent state`
- First executable task: `M2-T1 - Secure native Windows state persistence and coordination`
- M0 is complete as a design milestone. No updater, installer, release workflow, dependency, persistent Codex configuration, or live verification changed.
- M1-T1 is complete: the descriptive schema, strict bounded parser, synthetic fixtures, deterministic serialization, and crate-private TUF verification seam are implemented in `src/update/manifest.rs`.
- M1-T2 is complete: pure deterministic applicable-release selection is implemented in `src/update/selection.rs`; no updater, network, installation, or hook behavior was wired.
- M1-T3 is complete: `src/update/verify.rs` now provides a verifier-owned read-only authenticated-manifest boundary with no production constructor. The only constructor compiled for tests is explicitly synthetic byte binding and does not execute TUF verification. Selection accepts only this wrapper, and the runtime compatibility/broker authority remains unchanged.
- M2-T1 is incomplete after reconciliation: the Linux state store uses descriptor-relative operations, bounded versioned data, atomic replacement, and a required lease. Windows state reads/writes fail closed with `UnsafePersistence` pending secure implementation and fresh native tests. The original draft's native CI run `34597568124` does not validate this merged code.
- M2-T3 implementation is in progress: the broker writes bounded redacted observations to a launcher-owned audit not inherited by the child; an allow is `broker_allow_unconfirmed`, never proof of hook stdout. On Linux, eligible sessions can persist version/platform/surface-bound observations; Windows persistence remains disabled. Child exit status is unknown command evidence.
- Historical Linux and Windows observations are not current certificates. The current embedded production manifest has zero targets and ordinary runs stay unarmed.

## Read first

1. Read [distribution-roadmap.json](distribution-roadmap.json), the canonical structured roadmap.
2. Read [distribution-roadmap.md](distribution-roadmap.md), the generated readable rendering.
3. Reconcile branch, HEAD, origin, staged changes, and working-tree state.
4. Run:

   ```text
   cargo run --bin validate_distribution_roadmap -- --check
   ```

5. Execute the first task whose dependencies are complete. The next ready task is `M2-T1` (secure native Windows state persistence and verification).

## M0 decisions completed

- Startup update checks are enabled by default; installation always requires explicit consent.
- A Codex-version change and unresolved compatibility state trigger a bounded applicable-release check before the installed implementation is attempted, subject to coordinated backoff.
- Interactive choices are Install, Continue this time, and Skip this release. Skip applies only to the exact Codex/release pair and is reconsidered after a Codex version change or different release.
- Noninteractive launches never prompt or consume Codex input. Check, update, activation, and rollback logic stays outside the hook protocol process and hook stdout.
- A failed or unavailable update must continue with the known-good installed payload and current exact-certificate admission policy. A started Codex session must never be replayed or restarted.
- Capability success, genuine hook success, no hook invocation, hook incompatibility, and command failure are separate local outcomes. Local success never promotes project-wide reviewed support.
- Initial proposed targets are native Windows x64 `x86_64-pc-windows-msvc` with Windows 10 22H2+ and native Linux x64 `x86_64-unknown-linux-gnu` with glibc 2.31+. These are not validated installable support yet.
- The design uses user-scoped paths, a stable launcher, immutable versioned payloads, and an active pointer. Existing Cargo/package-manager installations are never silently overwritten and require explicit migration or instructions.
- Trust uses a pinned-root TUF design with bounded authenticated metadata, target hashes/lengths, expiry and rollback protection, threshold key rotation, explicit local rollback, and no authority over hook authorization. The reviewed library choices are recorded in the JSON.

## M1-T1 schema contract completed

- Manifest schema version 1 uses bounded snake_case fields and kebab-case enum values for release version, release notes, native asset target/OS/architecture/runtime/archive/length/SHA-256/origin/provenance, and exact compatibility records.
- Compatibility records explicitly nest the tuple and reviewed/experimental/excluded eligibility. Required hook event, protocol, tool, input schema, and response behavior are descriptive and do not change the runtime broker registry.
- Parsing rejects duplicate keys at any nesting level, unknown nested fields, duplicate asset or compatibility identities, malformed stable versions/prereleases, invalid hashes or lengths, unsupported schema versions, and contradictory runtime/compatibility records.
- Canonical serialization deterministically sorts asset and compatibility arrays. Parsing alone is untrusted; only a later successful TUF verification adapter may expose authenticated metadata, using the TUF target's authenticated bytes, length, and hash.
- Synthetic fixtures are under `tests/fixtures/distribution_manifest/`. They use no production trust anchors and do not establish reviewed support or native runtime-floor validation.
- This task did not implement selection, network fetching, persistent state, installation, startup prompts, release publication, or TUF cryptography.

## M1-T2 selection contract completed

- Selection accepts typed installed autoapprover/Codex versions, native target OS and architecture, runtime environment, local CLI surface, and the existing automatic/strict compatibility mode.
- It consumes only TUF-authenticated manifest wrappers, searches every supplied candidate, compares stable release versions numerically, rejects equal release versions and ambiguity, and never uses input order or publication date.
- It skips incompatible newer releases when an older release is still newer than installed and applicable. Empty catalogs, equal/older releases, missing platform/architecture assets, runtime floors, unknown runtime, malformed Codex versions, exclusions, and policy failures produce fixed-category outcomes.
- The selector models reviewed and experimental release metadata, but neither classification authorizes a hook. The normal launcher treats legacy `automatic` as strict and requires an exact native certification tuple; the embedded production manifest is empty. Exact exclusions take precedence over overlapping metadata eligibility.
- The selector returns release notes and current/new version data for a future consent UI, but it does not fetch, download, execute, install, activate, authorize, persist state, or modify the compatibility registry.

## M1-T3 compatibility and authorization boundary completed

- The documented stages are separate: untrusted bytes, structurally validated `ParsedManifest`, future TUF-authenticated `AuthenticatedManifest`, pure applicable-release selection, consented installation, and existing runtime Codex/broker authorization.
- `AuthenticatedManifest` has private content, no public deserialization or `Clone`, and no production constructor. Its test-only synthetic helper checks exact target name/length/SHA-256 byte binding only; it is not publisher-authentication evidence and does not claim to execute TUF.
- A parsed manifest, matching caller-supplied hash/length, selected release, user-approved update, or local observed success cannot arm the hook, edit the embedded certification manifest, override strict mode/exclusions, broaden the exact command, bypass identity/ancestry/session/cwd/schema/tool/version checks, or promote project-wide support.
- Focused tests cover metadata policy, exact exclusion, runtime rejection, and read-only-content. Historical Linux and Windows evidence is not promoted to current admission.
- Real TUF root/role/expiry/target verification is explicitly deferred to M5-T2. No network, installer, state, prompt, release publication, or live verification was added.

## M2-T1 state and coordination in progress

- State stores only installed/observed versions, successful-check metadata, bounded HTTP validators, exact Codex/release skip scope, backoff, and fixed failure categories. It rejects duplicate/unknown/corrupt/oversized/unsupported state and never defaults over corruption.
- The local update-state file is `update-state.json`, separate from the future installer's `active.json` payload pointer. On Linux, the store creates a private state directory for an eligible observation; an unarmed fallback does not create it.
- Writes use a same-directory temporary file, restrictive permissions where supported, sync-before-replace, and an atomic target replacement. Interrupted temporary files are ignored; the previous valid state remains authoritative.
- `CheckCoordinator` uses kernel-owned advisory file locks with bounded acquisition. `CheckLease` is required for read/modify/write transactions, contention is recoverable, and process termination releases the lock without stale-lock deletion.
- Original-branch native Windows state tests do not validate the reconciled implementation. Windows state persistence returns `UnsafePersistence` until secure path handling and native tests exist; diagnostics never authorize hooks.
- The Linux branch uses `rustix` descriptor-relative operations and kernel-released file locking. Same-user actors can still interfere with local records; state is not an authorization boundary. No network check, TUF verification, installer, or prompt exists.
- M2-T2 depends on the M1-T3 authenticated-manifest type boundary and the incomplete M2-T1. Real TUF construction remains owned by M5-T2; no parsed or hash-matched manifest may enter production selection before that verifier exists.

## M2-T3 compatibility outcomes and local diagnostics in progress

- `HookOutcome` models fixed categories including `broker_allow_unconfirmed`; a successful-exchange category is not inferred from broker allow or a child-written marker. `CommandOutcome` is independent; the launcher records unknown because a Codex child exit code is not command evidence.
- Multi-request sessions retain saturated bounded counters and aggregate conservatively: protocol failure outranks transport failure, compatibility rejection, and a broker allow; no invocation is reported only when no trusted broker entry occurred. A broker no-decision can include an authorization failure and is not classified as a compatibility rejection.
- Hook outcome records contain only fixed category names and bounded counters. No command text, payload, credentials, secrets, environments, child output, or arbitrary error text enters state or diagnostics. Hook stdout remains protocol-only.
- M2-T1 state records observations keyed by autoapprover version, Codex version, operating system, and surface. Same-identity sessions merge bounded counters; different versions remain separate, so an older finishing session cannot overwrite a newer observation.
- `diagnose` reports local observations separately from reviewed compatibility. It cannot alter the compiled registry or runtime broker authorization. Existing fallback, exit-status, exact-command, cwd, session, ancestry, and no-replay behavior remains unchanged.
- Linux eligible observations may create a private state directory. Windows persistence is disabled pending secure implementation. No network, updater, install, prompt, or live Codex verification was added.

## Update protocol

After each session:

- Record actual task status and evidence in `distribution-roadmap.json`.
- Regenerate Markdown with:

  ```text
  cargo run --bin validate_distribution_roadmap -- --write
  ```

- Re-run `--check`, formatting, relevant tests, and `git diff --check`.
- Update this handoff with the resulting commit, next executable task, blockers, and commands.
- Keep completion evidence tied to real files, commands, and host results. Do not infer release readiness from a plan, compilation, a successful Codex exit, or another session's unsupported claim.
- Keep release publication, tagging, installation, and live verification as separate explicit actions.

## Remaining concrete blockers

- `B-M4-M6-NATIVE-ACCEPTANCE`: proposed Windows/Linux runtime floors, installers, locked-binary activation, rollback, concurrent sessions, PATH/profile behavior, and uninstall still require native M4/M6 acceptance.
- `B-M5-TRUST-SETUP`: maintainers must later generate/protect the threshold signing keys, configure least-privilege GitHub signing/release environments, record fingerprints, and publish the bootstrap root. No keys, secrets, or GitHub settings were created here.
- `B-M6-NATIVE-HOSTS`: the Windows x64 laptop and Linux x64 workstation are required for isolated install/update/rollback/uninstall acceptance.

## Next task

`M2-T1` is the next task: implement secure native Windows state persistence and coordination, verify them on a Windows host, and independently review the combined tree. `M2-T3` diagnostics are only partial until that prerequisite and trustworthy hook-output evidence exist. `M2-T2` remains planned; production selection also requires the genuine M5-T2 TUF verifier.

## Boundaries

Do not treat roadmap milestones or local diagnostics as production certification. Native verification and release approval require separate recorded evidence and independent review.
