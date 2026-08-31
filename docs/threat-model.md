# Threat model

This threat model covers the hook-based architecture. Hooks provide a structured event boundary, but they do not make unconditional approval safe and they do not replace Codex's sandbox or authentication. The only verified production target is Linux, the local CLI launcher, and Codex CLI 0.151.0; all other versions and surfaces remain outside this model's compatibility claim.

## System and data flow

`codex-autoapprover run` resolves an official Codex executable, creates a random child-session token, and starts Codex with inherited stdin/stdout/stderr. For a verified version, it supplies a child-only `-c` hook override. Codex invokes the hook synchronously before a PermissionRequest reaches the normal approval prompt. The hook reads one JSON request, validates event and arming bindings, and either writes the exact one-request `allow` response to stdout or writes no decision. Codex then proceeds according to its own hook and permission semantics.

The hook input may include `session_id`, `cwd`, `hook_event_name`, `permission_mode`, `turn_id`, `tool_name`, and `tool_input`. The launcher token and expected cwd are inherited environment values. Hook invocations for matching hooks may be concurrent.

The experimental `verify-local-hook` path adds an exact local-version check, interactive confirmation, a temporary Git repository, `workspace-write` and `on-request` settings, a child-local hook override, and a redacted temporary audit sink. It does not isolate or replace the user's Codex authentication context, and the hook-trust bypass can allow other configured hooks to participate under Codex's documented composition rules.

## Assets

- user files and filesystem contents;
- credentials and authentication/session data;
- source repositories, Git history, branches, and remotes;
- network access and remote side effects;
- terminal input and output;
- Codex permission and approval decisions;
- launcher arming tokens and process identity;
- hook configuration and executable paths; and
- audit records and diagnostics.

## Trust boundaries

1. **User terminal and shell:** supplies input and displays output but can carry hostile content.
2. **Launcher:** resolves the executable, creates arming state, injects child-only configuration, and propagates status.
3. **Official Codex executable:** the agent runtime and hook caller; its identity must be validated.
4. **Hook process:** parses untrusted JSON and can return an approval decision.
5. **Codex sandbox and approval engine:** provides the underlying authority boundary.
6. **Spawned commands and descendants:** may inherit environment, print hostile data, and cause side effects.
7. **Filesystem and configuration:** stores executables, hooks, repositories, sessions, and logs.
8. **Network:** can deliver hostile content or receive authorized data.
9. **Installer/update channel:** can replace the launcher or hook definition.

## Threat actors and failure sources

Threats may originate from malicious repository content, prompt injection, model output, malicious command output, a compromised dependency, PATH substitution, a malicious local executable, a forged hook invocation, a concurrent session, a user misunderstanding, an accidental implementation error, unsupported schema changes, symlink attacks, or a compromised package/update channel.

## Threats and mitigations

| Threat | Impact | Likelihood | Mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Forged `PermissionRequest` JSON from a descendant or hostile process | Unauthorized allow | Medium | Random per-child token, protocol marker, cwd binding, strict event/field checks, no global state | Descendants can inherit the token; parent-process binding is not implemented |
| Verification child receives a different or repeated action | Unauthorized live side effect or invalid evidence | Medium | Exact target-version gate, exact `tool_input.command` guard, one recorded allow required, non-promotion on count mismatch | A malicious descendant can inherit the guard and invoke the hook with the same harmless string |
| Malicious repository content or prompt injection influences a real request | Dangerous command authorized | Medium | Treat tool input as untrusted; authorize only the current Codex event; warn that allow is consequential | Hook cannot determine semantic intent or model honesty |
| Malformed or oversized JSON | Parser crash, confused decision | Medium | Bounded read, strict JSON object parsing, no panics, empty decision on failure | Codex's handling of hook failures is release-dependent and must be tested |
| Unsupported schema or wrong hook event | Wrong event authorized | High | Exact `PermissionRequest` check, explicit schema/version policy, fail closed | Official schemas may evolve without a stable version field |
| Permanent/session-wide approval returned accidentally | Persistent over-authorization | High impact | Serialize only the documented `{behavior: "allow"}` one-request shape; no other approval fields | A future code defect or Codex semantic change could alter scope |
| Concurrent sessions share authorization | Cross-session approval | Medium | Unique token per launcher, cwd/session binding, no shared mutable approval state | Environment inheritance and weak process identity leave residual confusion risk |
| Multiple PermissionRequest hooks race | Unexpected allow/deny composition | Medium | Install only explicit hook when supported; document Codex's matching-hook concurrency and deny precedence | Other user, project, plugin, or managed hooks may still participate |
| PATH substitution or malicious Codex executable | Launcher runs attacker-controlled code | Medium | Resolve and display path, reject recursive self-resolution, avoid live config changes | User-controlled PATH and binaries remain trusted inputs |
| Hook configuration tampering or symlink attack | Arbitrary hook execution or wrong handler | Medium | No automatic installer yet; future installer must validate paths, permissions, hashes, and symlinks | Current child `-c` override does not protect a compromised host |
| Arming token appears in logs or child output | Session authorization disclosure | Medium | Never print token; hash tool metadata only; document descendant inheritance | A child process with environment inspection can read the token |
| Audit logs leak commands or secrets | Credential/source disclosure | Medium | No full command logging by default; hash/redact; protected paths and permissions | Hashes and metadata can still be sensitive |
| Codex changes hook schema or behavior | False compatibility or missed safety boundary | High | Empty allowlist until local evidence; exact fixtures; compatibility review | No textual integration can guarantee future semantic compatibility |
| Launcher or hook crashes | Terminal/process recovery issue | Low to medium | Ordinary inherited terminal avoids raw-mode management; propagate child status; test interruption and cleanup | Host failure or abrupt kill can still leave child/process state |
| Installer/update channel compromise | Code execution with user privileges | Low to medium | Signed/reviewed artifacts, verified update path, no silent Codex replacement, rollback plan | Supply-chain risk remains outside the hook protocol |

## Environment inheritance and malicious children

The launcher sets arming variables on the Codex child rather than globally. Standard child environment inheritance means shell commands, plugins, MCP processes, and other descendants may receive them. A descendant that knows the hook protocol could potentially invoke the hook directly while the token remains available. The MVP documents this limitation and must add stronger parent/process/session binding before public release.

## Residual risks and assumptions

The design assumes the host, terminal, user account, official Codex executable, and launcher artifact are not already compromised; the user intentionally armed the session; Codex's own authorization system behaves as documented; and the user understands that each allow can authorize a consequential request. Hooks reduce screen-parsing ambiguity but do not verify command intent, prevent prompt injection, or make repeated approval safe.

Protections against a fully compromised host, malicious official Codex build, arbitrary model behavior, all prompt injection, and all network/filesystem side effects are explicitly out of scope.

IDE-extension, desktop, remote, container, WSL, SSH-hosted IDE, and Codex cloud integration are independently unverified. A future IDE implementation must have its own persistent-hook composition, secure arming, session identity, and threat review; the current CLI child environment is not sufficient evidence.

## Pre-release security gates

Before release, the project MUST have a locally demonstrated supported hook flow, exact positive and negative protocol fixtures, malformed/oversized input tests, process/session binding tests, concurrency tests, executable and configuration path checks, secret-redaction tests, kill-switch and recovery tests, and a review of the effect of other matching hooks. Package/update integrity must be reviewed before distribution.
