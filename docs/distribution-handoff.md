# Distribution roadmap handoff

This is a planning handoff, not an updater implementation or release approval.

## Current state

- Repository: `slee7286/codex-autoapprover`
- Roadmap branch: `feat/distribution-roadmap`
- Roadmap source branch: `main`
- Inspected source commit: `296008527103e98b9d9f9f20fe6d4e8508346b21`
- Current milestone: `M0 — Product contract and installation/update design`
- First executable task: `M0-T1 — Contract and startup state machine`
- No updater, installer, release workflow, or persistent Codex configuration was changed by the roadmap task.
- Existing Codex hook authorization, compatibility, fallback, and live-verification evidence remain outside this roadmap change.

## Read first

1. Read [distribution-roadmap.json](distribution-roadmap.json), the canonical structured roadmap.
2. Read [distribution-roadmap.md](distribution-roadmap.md), the generated readable rendering.
3. Reconcile branch, HEAD, origin, staged changes, and working-tree state.
4. Run:

   ```
   cargo run --bin validate_distribution_roadmap -- --check
   ```

5. Execute the first task whose dependencies are complete. For the current roadmap, begin with `M0-T1`.

## Update protocol

After each session:

- Record actual task status and evidence in `distribution-roadmap.json`.
- Regenerate the Markdown with:

  ```
  cargo run --bin validate_distribution_roadmap -- --write
  ```

- Re-run `--check`, formatting, relevant tests, and `git diff --check`.
- Update this handoff with the next executable task, blockers, exact commit, and commands.
- Keep completion evidence tied to real files, commands, and host results. Do not infer release readiness from a plan, compilation, a successful Codex exit, or another session's unsupported claim.
- Keep release publication, tagging, installation, and live verification as separate explicit actions.

## Immediate design focus

M0 must settle the startup decision table, user-visible state transitions, supported native Windows x64/Linux x64 targets, Linux libc/minimum-runtime strategy, user-scoped installation ownership, Cargo/package-manager coexistence, bootstrap trust, signing/key rotation, and maintained-library choices. The initial release must not shadow `codex`, block noninteractive sessions, run updater logic inside the hook process, replay a started session, or turn local observations into reviewed compatibility.

## Open blockers

- The supported Windows build/runtime floor and Linux libc/minimum-runtime target require an explicit decision and native validation.
- Release signing/bootstrap trust/key rotation and one-time GitHub setup require maintainer action.
- Native install/update/rollback/uninstall and locked-binary acceptance require the Windows x64 laptop and Linux x64 workstation.

## Boundaries

Work only in `C:\Users\slee7\repos\codex-autoapprover-verification` and repository `slee7286/codex-autoapprover`. Do not spawn subagents, upgrade Codex, modify persistent Codex configuration, start live verification, publish a release, or mark a task completed without its recorded evidence.
