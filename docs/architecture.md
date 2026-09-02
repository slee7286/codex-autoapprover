# Proposed hook-based architecture

This document describes the authoritative implementation direction. The former PTY/screen-scraping design is retained only as historical proof-of-concept context and is not a production architecture.

## Context and goals

The launcher should preserve ordinary Codex by executing the user's existing official CLI as a normal child process. Codex remains responsible for its TUI, authentication, configuration, sessions, model selection, sandbox, plugins, and exit behavior. Automatic approval is a narrow, explicit `PermissionRequest` hook response, not terminal input automation.

The authoritative MVP path is hook-based. The old PTY/screen-scraping experiment is not a fallback or planned primary implementation. `run` and `print-hook-config` use a typed exact compatibility registry. `verify-local-hook` remains an experimental, one-session-only mechanism for the exact local target Codex 0.151.0; its reviewed evidence is recorded in that registry but the mechanism does not promote entries automatically.

The current repository is pre-alpha. The only verified production tuple is Linux, local CLI launcher, Codex CLI 0.151.0, `PermissionRequest`, `permission-request-v1`, observed `Bash`, and one-request structured allow. No live hook configuration is installed. The second isolated live verification met the clean-repository and cleanup gates; its concise non-sensitive evidence is recorded in `src/compatibility.rs` and `docs/compatibility.md`.

## Components

- **CLI parser:** separates launcher subcommands and the `--`-delimited Codex argument vector.
- **Official Codex resolver:** resolves `codex`, canonicalizes it for recursive self-resolution checks, and queries `--version`.
- **Compatibility registry:** matches exact Codex version, OS, local CLI surface, hook protocol, and reviewed release metadata.
- **Session/broker:** creates a unique private runtime directory and Unix socket, retains a random secret, and owns the final decision.
- **Local verification gate:** requires Linux, exact target-version equality, an interactive exact confirmation phrase, a temporary Git repository, and a child-only hook override.
- **Child-process launcher:** starts Codex with inherited stdin, stdout, stderr, environment, working directory, and user arguments.
- **PermissionRequest hook handler:** reads one bounded request, connects only to the bound socket, and prints a response only after the broker says `allow`.
- **Hook protocol parser:** validates JSON shape, event name, required fields, bindings, and supported internal protocol marker.
- **Decision engine:** runs inside the broker and combines event, cwd, compatibility, secret, peer UID, exact process identity, ancestry, and fail-closed policy.
- **Fail-closed response path:** writes only the exact structured allow object on success; all other paths write no decision.
- **Compatibility detector:** identifies the installed Codex version and consults the explicit verified allowlist.
- **Audit recorder:** emits redacted metadata/hashes without complete commands, tool input, credentials, or tokens.
- **Verification audit recorder:** records whether a single allow response was produced using only short hashes and temporary state; it does not claim that a hook event proves command success.
- **Configuration installer (later milestone):** may install or remove a reviewed hook while preserving unrelated Codex configuration; it is not implemented here.
- **Shutdown and exit propagation:** waits for the child, handles ordinary interruption, and maps the child's exit status to the launcher.

The broker uses Linux `SO_PEERCRED` through `rustix`. It records the child identity as `(PID, /proc/<pid>/stat start time, effective UID)`. A connection is eligible only when its kernel peer UID matches the launcher's effective UID and two stable, bounded `/proc` ancestry walks from the kernel peer PID contain that exact tuple. The hook never supplies or authenticates its own PID.

The default design intentionally does not allocate a second PTY. A normal child process inherits the terminal and avoids duplicating terminal emulation, raw-mode restoration, screen parsing, cursor tracking, and option-number assumptions.

## Interfaces

Conceptual interfaces are (the names are design seams, not current public Rust APIs):

```text
trait ApprovalSource {
    fn read_request(&mut self) -> Result<ApprovalEvent, ProtocolError>;
}

trait ApprovalResponder {
    fn allow_one_request(&mut self) -> Result<AllowResponse, ResponseError>;
}

struct ApprovalEvent {
    event_name: String,
    session_id: String,
    cwd: String,
    tool_name: String,
    tool_input: JsonValue,
}

enum DetectionResult {
    NoMatch,
    Approval(ApprovalEvent),
    Ambiguous(String),
    UnsupportedVersion(String),
}
```

The responder has no permanent-rule or session-wide operation. `ApprovalSource` treats stdin as hostile data, and the decision engine is the only component allowed to select `allow` for one current request. `DetectionResult::NoMatch` represents a normal non-approval event; ambiguity and unsupported versions always route to no decision.

## Component and request-flow diagram

```mermaid
flowchart LR
    U[User terminal] --> L[Launcher]
    L -->|inherit stdio + args + child env| C[Official Codex]
    C -->|PermissionRequest stdin JSON| H[Hook handler]
    H -->|bounded framed request + secret| B[Launcher-owned broker]
    B -->|SO_PEERCRED + /proc ancestry| I[Exact Codex identity]
    B --> D[Decision engine]
    D -->|allow/no-decision| H
    H -->|structured allow or empty stdout| C
    B --> A[Redacted audit metadata]
    C --> X[Exit status]
    X --> L
```

Request flow:

1. The user starts `run` and explicitly chooses to use this launcher, or starts the separate `verify-local-hook` experiment.
2. The resolver finds the official executable and reads its version.
3. The compatibility detector enables automatic hook registration only for the exact verified registry tuple. Unknown versions and unsupported surfaces remain unarmed. The verifier has a separate exact 0.151.0 target gate and never edits the registry automatically.
4. The launcher creates a unique private runtime directory and socket, starts the listener, then launches the exact Codex child with only the socket location, protocol marker, and secret needed by the hook.
5. The launcher records the child's exact `(PID, start time, effective UID)` before the broker can authorize.
6. Codex synchronously starts the configured `PermissionRequest` hook before surfacing its normal prompt.
7. The hook parses one bounded request and connects to the socket. The broker obtains kernel peer credentials, validates the secret, performs bounded stable ancestry checks, applies the exact compatibility/cwd/tool policy, and returns allow or no-decision.
8. The hook prints the documented one-request structured allow only after broker allow; otherwise it prints nothing. Codex applies its normal hook composition and permission semantics.
9. The child exits or is interrupted; the broker stops accepting decisions, workers join, the socket/private directory are cleaned, and the launcher propagates the child exit result.

## Armed/disarmed state machine

```mermaid
stateDiagram-v2
    [*] --> Disarmed
    Disarmed --> Resolving: run requested
    Resolving --> Disarmed: unknown or unsupported version
    Resolving --> Armed: verified version + broker created
    Armed --> HookInvoked: PermissionRequest starts
    HookInvoked --> Allowed: broker identity + policy checks
    HookInvoked --> Declined: unarmed, malformed, unknown, or mismatch
    Allowed --> Armed: hook process exits
    Declined --> Armed: hook process exits
    Armed --> Disarmed: child exits / emergency disable
    HookInvoked --> Disarmed: launcher failure / emergency disable
    Disarmed --> VerificationConfirmed: verify-local-hook + exact phrase
    VerificationConfirmed --> Armed: exact target + temporary repo
    VerificationConfirmed --> Disarmed: EOF, timeout, wrong phrase, or mismatch
    Armed --> Disarmed: verification child exits / cleanup
```

`Allowed` is one request only. It does not transition to a permanently authorized state. Multiple Codex requests may produce multiple independent hook invocations while the child remains armed, and each has the same consequential warning.

## Concurrency design

Codex may invoke matching command hooks concurrently, and multiple hook sources may participate. The hook handler must be reentrant and must not use a process-global mutable approval flag. Each launcher invocation receives a distinct broker secret/socket; each connection is independently checked against the exact child identity and cwd policy.

The broker accepts at most 16 active connections, handles each connection in a bounded worker, applies a two-second read/write timeout, and processes one request per connection. A stalled or malformed client cannot occupy the listener indefinitely. Requests can be sequential or concurrent within one Codex session. Shutdown sets an atomic stop flag before the listener and workers are joined; a final identity check prevents a child that has exited or been reparented from receiving a decision.

The observed `Bash` constraint is part of the compatibility tuple: other tool types receive no decision until independently verified.

The broker is intentionally Linux-only. `$XDG_RUNTIME_DIR` is used only when it is a non-symlink directory owned by the effective user with mode 0700 and usable for a socket; otherwise a unique 0700 fallback directory is created. Socket paths are unique, checked before bind, set to mode 0600, and validated as owned sockets. Cleanup refuses to delete symlink or non-socket replacements.

## Proposed Rust module layout

```text
src/
  main.rs
  cli.rs
  codex.rs
  launcher.rs
  arming.rs
  hook.rs
  protocol.rs
  decision.rs
  broker.rs
  procfs.rs
  audit.rs
  compatibility.rs
  error.rs
tests/
  hook_mvp.rs
```

The listed modules are implementation seams, not evidence that every future property is complete. Configuration installation should be a later module or separate command with its own review.

## Linux-first plan

Linux is the verified first target because the evidence is Ubuntu-based and ordinary inherited terminal I/O is straightforward to validate there. The verified path covers process resolution, `-c` hook registration, child environment behavior, request parsing, response handling, interruption, exit status, argument forwarding, and temporary test configuration without writing the user's live Codex home.

Future registry entries must first demonstrate one harmless, authenticated `PermissionRequest` invocation using a temporary or otherwise isolated configuration. Until independently reviewed, each new tuple remains unverified and `run` launches it with automation disabled.

## Unsupported platforms and future IDE integration

Windows native compilation and fake-runtime validation now cover executable resolution, inherited terminal behavior, environment inheritance, interruption/cancellation, process creation, quoting, exit codes, and configuration-path nonmutation. Windows Codex 0.152.1 remains candidate/unverified: no live `PermissionRequest` has been observed and no structured allow has been returned to real Codex. macOS still requires independent validation, and neither platform inherits Linux hook compatibility claims. VS Code/IDE, desktop, remote, container, WSL, SSH-hosted IDE, and Codex cloud surfaces are also unsupported and unverified.

IDE-extension integration is planned separately. It needs a persistent-hook composition design and secure arming/process binding that can distinguish the intended IDE session; the current child-local CLI design and evidence cannot be reused as that guarantee.

## Testing architecture

Tests should include:

- protocol fixtures for valid armed PermissionRequest, unarmed request, wrong event, missing fields, malformed JSON, empty input, oversized input, unknown fields, and stdout purity;
- arming/broker tests for random distinct secrets, missing/incorrect/oversized secrets, cleanup, token non-disclosure, peer UID, exact PID/start-time ancestry, stale sessions, and concurrent sessions;
- a fake Codex executable for exact argument forwarding, environment propagation, exit status, missing executable, PATH resolution, and recursion protection;
- compatibility tests for verified versions, unknown/malformed versions, and the fact that legacy option-1 evidence does not establish hook support;
- PTY-free process integration tests for inherited stdin/stdout/stderr where testable and normal interruption;
- verification lifecycle tests for exact version binding, confirmation aborts, temporary repository cleanup, child-local overrides, action restriction, audit redaction, and non-promotion;
- broker framing tests for length limits, truncation, trailing/duplicate fields, timeouts, active-connection bounds, sequential/concurrent requests, shutdown, and socket permissions; and
- fuzz/property tests for JSON limits, unknown fields, and decision-state transitions; and
- real opt-in Codex integration tests only after a supported version is locally demonstrated, never with unattended destructive commands.

Positive fixtures alone are insufficient. Tests must assert that malformed, ambiguous, unarmed, unsupported, or mismatched requests receive no allow response.

## Why screen parsing was abandoned

The legacy Expect proof showed that option 1 could select one approval in one Ubuntu/Codex 0.151.0 scenario. It did not establish stable numeric ordering, terminal wording, ANSI behavior, or semantic association with the requested command. Screen scraping also introduces redraw races, terminal-control injection, cursor/width/locale differences, and raw-mode recovery obligations. The documented `PermissionRequest` hook supplies a structured event and response path before the prompt, so it is the authoritative primary implementation.

## Packaging and future App Server backend

Packaging is a later milestone. It must not replace Codex, silently edit configuration, or install a hook without explicit review, and it must authenticate artifacts and provide removal/recovery guidance.

The first verifier deliberately does not install anything: it relies on the existing official authentication context, runs in a temporary repository, and supplies the hook through `-c` for that child. A future installer must be a separate reviewed component.

A future direct Codex App Server backend may provide an even more structured approval transport. It would still require protocol negotiation, request-scope validation, authentication review, and fail-closed behavior. The hook backend should remain separate from that future transport while sharing decision and audit policy.

## Open questions

- Which future Codex releases and hook protocol versions can be demonstrated safely and admitted independently?
- Does each newly supported Codex version reliably inherit arbitrary child environment variables into synchronous hooks?
- How should a future platform-specific implementation provide equivalent process/session binding without weakening this Linux threat boundary?
- What is the exact `-c` merge behavior when user, project, plugin, managed, and child-only hook sources coexist?
- How should `print-hook-config` and a future installer preserve unrelated hooks and trust-review state?
- What platform-specific process and signal behavior must be documented before macOS or Windows support?
