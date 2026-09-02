# Hook protocol

This document separates verified official documentation, local observations, and project behavior. Official hook behavior can change; the current official page is the release reference. Production compatibility is limited to Linux, the local CLI launcher, and Codex CLI 0.151.0.

## Officially documented facts

The [official OpenAI Codex hooks documentation](https://developers.openai.com/codex/hooks) currently documents:

- the exact event name `PermissionRequest`;
- hook configuration in `hooks.json` or inline `[hooks]` tables in `config.toml`;
- a command hook handler with `type = "command"` and a `command` string;
- one JSON object on stdin for every command hook;
- common input fields `session_id`, `transcript_path`, `cwd`, `hook_event_name`, and `model`;
- `permission_mode` on `PermissionRequest` and other turn-scoped events;
- PermissionRequest fields `turn_id`, `tool_name`, `tool_input`, and optional `tool_input.description`;
- synchronous PermissionRequest execution before the normal approval prompt, when a request needs approval;
- the structured allow response:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow"
    }
  }
}
```

- a structured deny response with `behavior: "deny"` and an optional message;
- if no matching hook decides, Codex uses the normal approval flow;
- if multiple matching hooks decide, deny wins; otherwise allow proceeds without surfacing the approval prompt;
- `updatedInput`, `updatedPermissions`, and `interrupt` are not supported for PermissionRequest and fail closed today;
- plain text on stdout is ignored for PermissionRequest; and
- exit 0 with no output is treated as hook success and Codex continues.

The documentation also states that matching hooks from multiple files run and multiple matching command hooks for one event launch concurrently. Hook commands run with the session cwd. Non-managed hooks require trust review, and `--dangerously-bypass-hook-trust` can bypass persisted trust for a deliberately vetted one-off invocation.

## Local Codex observations

The reviewed local target was Linux with the locally resolved official command reporting `codex-cli 0.151.0`. Its help exposed `-c/--config`, `--dangerously-bypass-hook-trust`, and ordinary Codex process options. `codex features list` reported:

```text
hooks  stable  true
```

The generated child-only inline `-c` hook override was accepted by the target. The reviewed second isolated live verification produced one real `PermissionRequest`, one structured allow response, and an HTTP/2 200 result for the exact harmless curl request without an observed interactive approval prompt. The temporary repository was clean immediately before and after the child, and temporary state cleanup completed. No live hook configuration was changed. This evidence supports only the typed registry entry; it does not imply compatibility with later versions or other surfaces.

## Project handler contract

The Rust handler currently:

1. reads at most 1 MiB plus one byte from stdin;
2. requires a JSON object;
3. requires `hook_event_name` exactly equal to `PermissionRequest`;
4. requires non-empty `session_id`, `cwd`, `tool_name`, and `tool_input`;
5. requires the inherited socket location, the exact marker `CODEX_AUTOAPPROVER_HOOK_PROTOCOL=permission-request-v1`, and a valid random session secret only to connect to the broker;
6. sends an internal `permission-binding-v1` framed request to the broker; the broker alone checks exact version/cwd, `Bash`, secret, `SO_PEERCRED`, and `/proc` ancestry;
7. in the isolated verification path, the broker additionally requires `tool_input.command` to equal the platform-specific canonical probe: `curl -I https://example.com` on Linux or `curl.exe -I https://example.com` on native Windows;
8. serializes only the documented allow response after broker allow; and
9. returns exit 0 with empty stdout for every decline, parse failure, broker failure, or disconnected session.

Unknown JSON fields are ignored by the parser but never broaden a decision. The project does not use numeric options, terminal text, ANSI sequences, or a PTY to make a hook decision.

The marker, exact-version, local-surface, and cwd checks are project policy, not official Codex fields. Unknown hook fields are ignored for forward compatibility, but they cannot satisfy or broaden a decision. The internal broker rejects duplicate top-level or nested fields, unexpected envelope fields, unsupported versions/types, malformed framing, trailing data, and oversized messages. The secret is intentionally not printed. Descendants may inherit it, but it cannot authorize without kernel peer credentials and exact ancestry.

The verifier gives the broker an audit path in its own temporary state. The broker records only an allow marker and short hashes of tool name and tool input; the hook does not own the allow decision or audit sink. If the audit sink cannot be written, the broker declines rather than allowing. The verifier establishes a local committed Git baseline and checks status immediately before launch and after child exit, including ignored entries; status diagnostics contain only porcelain status codes and paths.

## Decline and malformed behavior

The official documentation establishes that no stdout output with exit 0 is a successful no-decision path. It does not fully specify every malformed hook input/output edge case in the current page. This implementation chooses empty stdout and exit 0 for malformed or unarmed input so Codex can continue its ordinary approval flow, while sending only a redacted reason to stderr.

The exact way Codex surfaces hook process errors, timeouts, termination, or malformed responses must be verified in a real supported-version integration test before release. The handler itself never emits malformed JSON or unrelated stdout.

## Environment inheritance

The official hooks page documents plugin-specific environment variables and says hook commands run with the session cwd. The second isolated verification demonstrated the required child environment reaching the real hook path for this target. The launcher passes only the socket location, internal marker, and random secret needed by the hook. Descendants can inherit those values and may invoke the hook or cause denial of service, but the broker independently obtains peer identity from the kernel and checks live ancestry. This is not perfect same-user isolation.

## Binding sequence

The launcher creates a private broker and listener, launches the exact Codex child, records its PID/start-time/effective-UID tuple, and then permits decisions. Codex launches the hook; the hook connects and sends the bounded request. The kernel supplies peer PID/UID/GID, the broker validates the secret and bounded ancestry, and returns allow or no-decision. The hook returns structured allow or no output. When Codex exits or is interrupted, the broker stops, workers join, and the socket/private directory are removed.

## Schema versions and open questions

The official page refers to generated schemas but warns that a main-branch schema may include fields absent from the current release. The documented PermissionRequest input has no project-consumable schema-version field. This repository therefore treats the installed Codex version plus the project protocol marker as separate compatibility gates and rejects unknown Codex versions before arming.

Still open:

- whether empty stdout is preserved as normal approval on all supported releases;
- timeout and non-zero-exit semantics for PermissionRequest specifically;
- exact environment inheritance into synchronous hooks; and
- interaction with other matching hooks and trust sources.

IDE-extension integration is intentionally not supported. It requires a separate persistent-hook composition model and secure arming/process-binding design, followed by independent verification; local CLI evidence does not transfer to VS Code, desktop, remote, container, WSL, SSH-hosted IDE, or cloud surfaces.

## Synthetic examples

These examples use synthetic identifiers and a harmless command string; they are fixtures, not evidence of a live Codex invocation.

Input:

```json
{
  "session_id": "sess_synthetic_001",
  "cwd": "/tmp/codex-hook-fixture",
  "hook_event_name": "PermissionRequest",
  "permission_mode": "default",
  "turn_id": "turn_synthetic_001",
  "tool_name": "Bash",
  "tool_input": {
    "command": "printf synthetic"
  }
}
```

Armed output:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow"
    }
  }
}
```

Unarmed, unknown-event, malformed, mismatched-cwd, or oversized input: exit 0, empty stdout, and no allow decision.
