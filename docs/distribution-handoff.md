# Distribution roadmap handoff

This is a planning handoff, not an updater implementation, installer, release approval, or compatibility promotion.

## Current state

- Repository: `slee7286/codex-autoapprover`
- Roadmap branch: `feat/distribution-roadmap`
- Roadmap base commit before this M0 update: `cd82e224e9084b6c8cc8f479e2e932e13c97c96c`
- Roadmap source branch: `main`
- Inspected source commit: `296008527103e98b9d9f9f20fe6d4e8508346b21`
- Roadmap revision: `2`
- Current milestone: `M1 — Compatibility manifest and release selection`
- First executable task: `M1-T1 — Versioned release manifest schema`
- M0 is complete as a design milestone. No updater, installer, release workflow, dependency, persistent Codex configuration, or live verification changed.
- Existing Linux 0.151.0 and native Windows 0.153.2/0.154.0 compatibility records and authorization behavior remain unchanged.

## Read first

1. Read [distribution-roadmap.json](distribution-roadmap.json), the canonical structured roadmap.
2. Read [distribution-roadmap.md](distribution-roadmap.md), the generated readable rendering.
3. Reconcile branch, HEAD, origin, staged changes, and working-tree state.
4. Run:

   ```text
   cargo run --bin validate_distribution_roadmap -- --check
   ```

5. Execute the first task whose dependencies are complete. The next ready task is `M1-T1`.

## M0 decisions completed

- Startup update checks are enabled by default; installation always requires explicit consent.
- A Codex-version change and unresolved compatibility state trigger a bounded applicable-release check before the installed implementation is attempted, subject to coordinated backoff.
- Interactive choices are Install, Continue this time, and Skip this release. Skip applies only to the exact Codex/release pair and is reconsidered after a Codex version change or different release.
- Noninteractive launches never prompt or consume Codex input. Check, update, activation, and rollback logic stays outside the hook protocol process and hook stdout.
- A failed or unavailable update continues with the known-good installed payload and current automatic compatibility policy. A started Codex session is never replayed or restarted.
- Capability success, genuine hook success, no hook invocation, hook incompatibility, and command failure are separate local outcomes. Local success never promotes project-wide reviewed support.
- Initial proposed targets are native Windows x64 `x86_64-pc-windows-msvc` with Windows 10 22H2+ and native Linux x64 `x86_64-unknown-linux-gnu` with glibc 2.31+. These are not validated installable support yet.
- The design uses user-scoped paths, a stable launcher, immutable versioned payloads, and an active pointer. Existing Cargo/package-manager installations are never silently overwritten and require explicit migration or instructions.
- Trust uses a pinned-root TUF design with bounded authenticated metadata, target hashes/lengths, expiry and rollback protection, threshold key rotation, explicit local rollback, and no authority over hook authorization. The reviewed library choices are recorded in the JSON.

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

`M1-T1` should define the bounded, strictly validated release manifest: target OS/architecture/runtime, exact Codex compatibility tuple, version, release notes, provenance, authenticated hashes/lengths, prerelease/downgrade rules, and the rule that metadata cannot authorize runtime hooks.

## Boundaries

Work only in `C:\Users\slee7\repos\codex-autoapprover-verification` and repository `slee7286/codex-autoapprover`. Do not spawn subagents, upgrade Codex, modify persistent Codex configuration, start live verification, install software, publish a release, tag a release, or mark future support verified without its recorded evidence.
