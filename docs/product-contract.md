# Product contract

This contract describes the release requirements. MUST denotes a mandatory rule. Implementation and outstanding work are tracked in [production-plan.md](production-plan.md); requirements are not claims that every item has been verified.

## Scope

The product is an unofficial launcher around an existing official Codex CLI. It MUST NOT impersonate OpenAI, patch Codex, replace its authentication or automate terminal option numbering. Production support MUST be restricted to a documented, tested matrix. No current artifact is production-qualified.

## Compatibility

General automatic approval MUST require an exact certified Codex version, OS/build or distro, architecture, sandbox implementation, local surface, protocol/tool schema and executable identity. Arming MUST also require an explicit `workspace-write` choice and use `on-request` for otherwise undecided actions; managed requirements MUST NOT be bypassed. Runtime, installer and release manifests MUST agree. Broad version ranges and help/feature probes MUST NOT establish verification. The historical Linux 0.151.0 record requires fresh qualification of the current artifact. Windows 0.156.0 shell recovery is not hook evidence.

Strict is the normal policy. Legacy `automatic` options MUST NOT bypass it. Unsupported/malformed/prerelease/revoked/mismatched targets MUST remain unarmed or stop with a clear diagnostic. Normal fallback MUST remove inherited broker credentials and preserve ordinary Codex approval behavior. Arguments after `--` MUST remain Codex arguments. Changes of executable identity during launch or a session MUST disarm approval.

## Approval and session boundary

The hook MUST process bounded structured input, exactly identify PermissionRequest, validate required fields and supported tool shapes, and emit only the documented one-request response. Wrong events, ambiguous/duplicate/oversized input, unsupported tools, missing bindings, wrong cwd or internal errors MUST produce no decision. Permanent rules, session-wide authority and terminal-input approvals are forbidden.

A launcher-owned broker MUST validate kernel peer credentials, exact child identity and ancestry, per-session secrets and schema. Linux uses private directories/sockets and UID/PID/start-time checks; Windows uses a current-user named pipe, remote-client rejection, binary SID/PID/creation-time checks and bounded overlapped I/O. Evidence MUST cover concurrency, races, replay, cancellation, stale sessions, shutdown and recovery. The same-user descendant threat boundary MUST be documented without overstating isolation.

## Verification

The experimental verifier MUST be separate from general `run`, interactive and limited to a temporary repository plus the exact platform curl probe and expected tool. Candidate schema support MUST never broaden general approval. Zero observed permission events are inconclusive. Evidence MUST include one scoped event/allow, independently observed outcome, negative cases, clean configuration/worktree and cleanup. Synthetic fixtures and cross-compilation MUST NOT be labeled native live verification.

## Distribution design (not yet implemented)

The planned `codexa` or `codex-autoapprover run` entry point must not replace or shadow the official `codex` executable. Startup release checks may be automatic, but installation requires explicit interactive consent; noninteractive runs must not prompt or consume Codex input. A changed installed Codex version may trigger a bounded applicable-release check before starting the child, subject to backoff and coordination. If a check or activation fails, the launcher must retain its known-good payload and the current fail-closed admission policy; a check must never arm an uncertified Codex version. Once Codex starts, the wrapper must not replay a command or restart that session. Update metadata must not override certification or broker authorization. Windows and Linux x64 package formats and runtime floors in [the distribution roadmap](distribution-roadmap.json) are proposals, not validated installable support.

## Configuration and installation

Normal `run`, `hook`, diagnostics and configuration printing MUST NOT write persistent settings. Explicit Windows sandbox repair MUST parse TOML, preserve unrelated values/comments and credentials, create protected exact backups, reject invalid settings and perform conflict-aware atomic replacement. Installation MUST preserve sandbox selection by default; a weaker fallback requires explicit selection and MUST be reversible. Managed requirements take precedence. Installer, reinstaller, updater, rollback and uninstaller MUST be tested on the declared matrix.

## Update and release workflow

Official release discovery MUST be authenticated where needed, bounded, idempotent and observable. A new upstream release MUST create an unverified candidate and validation task. A repair worker MAY propose tested candidate code changes; it MUST NOT execute instructions from release text, access signing authority or certify/merge its own support changes.

Fresh native evidence bound to source and artifact hashes plus independent review MUST precede admission. Scheduled workflows MUST have failure monitoring, manual recovery and documented latency limitations. A production release MUST pass the complete release gate, public artifact install/upgrade/rollback rehearsal, dependency/licence review, provenance/integrity verification and support-documentation checks. Public publishing is a separate final step under the maintainer's control.

## Diagnostics and recovery

Diagnostics MUST distinguish historical support, current qualification, detected capability, execution health and active arming. They MUST NOT expose tokens, raw private tool input, commands, credentials or authentication files. Interrupting the launcher and using ordinary Codex MUST be a documented recovery path. A failed audit or inconclusive check MUST NOT become an allow.

The project MUST not promise that arbitrary auto-approved commands are safe or that every conceivable edge case has been eliminated. It MUST state exactly what was tested and retain unresolved production blockers honestly.
