# Product contract

This is the intended normative contract for `codex-autoapprover`. **MUST** and **MUST NOT** are mandatory requirements. **SHOULD** and **SHOULD NOT** are strong defaults that require a documented reason to change. **MAY** describes an optional capability. The only verified production tuple is Linux + local CLI launcher + Codex CLI 0.151.0.

## Product identity and status

The product MUST be an unofficial, independent launcher around a user's existing official Codex CLI. It MUST NOT present itself as Codex or OpenAI software and MUST NOT replace, patch, or reimplement the official agent runtime.

The repository is pre-alpha. The current implementation provides launcher plumbing, a hook handler, diagnostics, configuration rendering, synthetic tests, and one narrowly reviewed production compatibility entry. It MUST NOT generalize that entry to other versions, operating systems, or surfaces.

The external legacy evidence is limited to Ubuntu Linux, Codex CLI 0.151.0, an Expect proof of concept, and option 1 accepting a harmless `curl -I https://example.com` network escalation. Numeric option order MUST NOT be treated as an interface or hook support evidence.

## Launcher behavior

`run` MUST resolve the user's existing official `codex` executable and MUST refuse recursive self-resolution. It MUST verify the exact compatibility tuple before arming, preserve the user's working directory, inherited environment subject to documented launcher variables, stdin, stdout, stderr, Codex arguments, normal terminal behavior, and exit status as far as the platform permits.

The launcher MUST start Codex as an ordinary child process with inherited terminal I/O by default. It MUST NOT allocate a second PTY unless a later compatibility investigation proves that inheritance is insufficient. It MUST support normal terminal interruption, including Ctrl-C behavior appropriate to the platform.

The launcher MUST NOT modify Codex authentication, session data, sandbox settings, rules, or live configuration. A future configuration installer MUST be separate from `run`, explicit, reviewable, and reversible.

## Hook behavior

The hook MUST read exactly one bounded JSON request from stdin and MUST identify the event as exactly `PermissionRequest`. It MUST reject malformed, oversized, non-object, unknown-event, unsupported-schema, and incomplete requests without an approval decision. Unknown fields may be ignored under the documented forward-compatible parsing policy; they MUST NOT broaden a decision.

The hook MUST read bounded input and connect only to the launcher-owned session socket. The launcher-owned Linux broker MUST verify the random session secret, kernel `SO_PEERCRED` PID/UID/GID, and exact Codex process identity `(PID, /proc/<pid>/stat start time, effective UID)` before deciding. The peer UID MUST match the launcher's effective UID, and two stable ancestry walks from the kernel peer PID MUST contain the exact Codex identity. The hook MUST NOT make an allow decision from inherited environment metadata alone.

When all checks succeed, the hook MUST return exactly one structured `allow` decision for the current PermissionRequest. The response MUST NOT contain a permanent rule, session-wide authority, updated permissions, or unrelated fields. The hook MUST never return a screen key, numeric option, cursor movement, or terminal input.

When the process is unarmed or any check fails, the hook MUST return no decision. The current implementation represents this as exit 0 with empty stdout, consistent with the official documentation's no-output success behavior. Diagnostics MAY go to stderr but MUST NOT contain the full command, secrets, or token.

## Session-scoped arming and concurrency

Arming MUST apply only to the Codex child started by `run`. The launcher MUST NOT create global armed state or enable unrelated Codex processes. Each launcher invocation MUST generate a distinct random secret and private socket, and concurrent sessions MUST NOT share broker state.

Codex may invoke matching command hooks concurrently. The hook MUST be stateless across invocations or use a session store with explicit per-session isolation. One hook invocation MUST authorize at most its one current request; it MUST NOT infer approval from another invocation. Repeated requests in an armed session remain individually consequential and MUST be visible in audit metadata.

The child environment MAY be inherited by commands launched by Codex. The secret and socket are defense in depth, not a privilege boundary. A malicious process already running as the same user inside the exact authorized descendant tree remains in scope and may cause denial of service or invoke the hook binary.

The experimental `verify-local-hook` command MUST remain separate from `run`. It MUST detect the local official executable and exact platform target (`0.151.0` on Linux or `0.152.1` on native Windows), require an interactive exact confirmation phrase generated from that detected version, and use a temporary Git repository as cwd. It MUST pass the user's existing authentication context through inheritance without copying, printing, or modifying authentication data. It MUST use only child-local `-c` hook configuration and MUST remove its temporary state after the child exits.

The verification prompt MUST authorize only the platform-specific canonical probe: `curl -I https://example.com` on Linux and `curl.exe -I https://example.com` on native Windows. The verification hook MUST decline unless the request exposes a `tool_input.command` string equal to that exact platform-specific action. The verifier MUST set `workspace-write` sandboxing, `on-request` approvals, and no full-access or never-approve option. Incorrect confirmation, EOF, non-interactive input, timeout, interruption, version mismatch, missing hook evidence, multiple allows, dirty temporary state, or a non-success child exit MUST prevent compatibility promotion.

## Compatibility rules

The project MUST maintain a typed compatibility registry across Codex version, operating system, surface, hook event/protocol, observed tool type, response behavior, verification status/method, and autoapprover release. A Codex version MUST NOT be called supported because its UI resembles an earlier version, its generic feature flag is enabled, or a legacy option-numbering proof exists.

Unsupported or unverified versions MUST run with automation disabled or fail with a clear error. Exactly Linux local CLI Codex 0.151.0 is verified. The broker applies the version, surface, protocol, and observed `Bash` checks independently of inherited environment metadata, so a forged or stale environment receives no decision.

The verified entry records release `0.1.0`, hook event `PermissionRequest`, project protocol/schema marker `permission-request-v1`, response behavior one-request structured allow, and isolated live end-to-end verification. Compatibility with this release MUST NOT be inferred for 0.150.x, 0.152.x, any other version, macOS, Windows, VS Code/IDE, desktop, remote, container, WSL, SSH-hosted IDE, or Codex cloud.

Numeric approval ordering, terminal wording, ANSI sequences, cursor position, and screen scraping MUST NOT be compatibility inputs for the authoritative implementation.

## Audit behavior

The launcher SHOULD record local metadata for launch, compatibility, decision, decline, and failure events. It MUST NOT log complete tool input, commands, credentials, or tokens by default. Hashes, event names, version, cwd hash, timestamps, and redacted identifiers MAY be recorded.

Audit output MUST be protected against unsafe symlink following and unexpected permissions when persistent files are introduced. Failure to audit MUST NOT turn a declined request into an allow.

## User-visible commands and modes

The product MUST provide these conceptual operations:

- `run`: launch the official Codex child and arm only when the exact version is verified;
- `hook`: handle one Codex `PermissionRequest` invocation;
- `diagnose`: report non-sensitive local facts;
- `print-hook-config`: print, but never write, the exact configuration snippet for a verified installation;
- `verify-local-hook`: run one explicit, isolated, non-promoting local verification.

There MUST be a visible warning when automatic approval is armed. `diagnose` MUST report whether the current process is armed, the resolved path, installed version, compatibility result, platform status, and whether configuration was checked without exposing secrets. An emergency kill switch MUST disarm automatic responses immediately.

The verifier MUST print the exact harmless action and its confirmation phrase before launch. It MUST report distinct redacted evidence for hook invocation/allow, child result, temporary repository state, and cleanup. It MUST NOT print the arming token or persist full commands, tool input, credentials, or environment contents.

## Installation and uninstallation invariants

Installation and uninstallation, when implemented, MUST NOT replace the official Codex executable, alter Codex authentication, copy credentials, change Codex rules, or silently alter existing hooks. They MUST show the exact hook command and configuration location, preserve unrelated hook entries, validate permissions and symlinks, and provide a reversible removal path.

`run` and `print-hook-config` MUST NOT write live Codex configuration. No installer is part of this milestone.

The verifier MUST NOT write persistent Codex configuration, alter authentication, create approval rules, use `--yolo`, use full access, or silently fall back to an approval bypass. It MAY use Codex's documented one-off hook-trust bypass solely to make the child-local hook runnable, with a prominent warning that other configured hooks may still participate.

## First Linux beta acceptance criteria

The first Linux beta MAY claim support only after:

1. one exact Codex version and hook schema have been locally demonstrated with a harmless, temporary test;
2. ordinary child inheritance preserves arguments, terminal I/O, environment behavior, interruption, and exit status;
3. protocol tests cover valid armed allow, unarmed decline, wrong event, missing fields, malformed/empty/oversized input, unknown fields, and stdout purity;
4. arming tests cover distinct tokens, missing/incorrect tokens, cwd mismatch, cleanup, recursion protection, and concurrent sessions;
5. version tests show malformed and unknown versions fail closed and legacy option-1 evidence is not treated as hook support;
6. a real opt-in integration test confirms Codex receives the structured allow and does not show the ordinary prompt for that request;
7. failure, kill-switch, and recovery behavior have been reviewed; and
8. the threat model, compatibility matrix, and release warning identify residual risks.

## Non-goals

The product MUST NOT claim to make automatic approval safe, understand model intent, prevent prompt injection, replace Codex's sandbox or authentication, bypass approval for unverified events, select permanent rules, or support operating systems and Codex versions without evidence. The legacy PTY/screen-scraping approach MAY be retained only as historical proof-of-concept context; it MUST NOT remain the primary implementation plan.

The verifier MUST NOT promote a version automatically merely because its command completed. The reviewed second live run supplied evidence that the exact `PermissionRequest` event was received, the exact one-request response was returned, the harmless network command completed, no manual approval was observed, no persistent rule/configuration changed, the child exited normally, and cleanup completed. Future entries require the same review independently. The verification mechanism itself remains experimental.

IDE-extension integration is a separate future milestone. It requires a persistent-hook composition model and secure arming/process binding design, followed by independent verification; CLI evidence does not transfer to IDE, desktop, remote, container, WSL, SSH-hosted, or cloud surfaces.
