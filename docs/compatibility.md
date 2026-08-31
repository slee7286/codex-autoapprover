# Compatibility matrix

This matrix distinguishes reviewed production compatibility from the experimental verification mechanism and historical UI evidence. Compatibility is an exact tuple, not a version-only claim.

| Compatibility area | Evidence | Status | Supported claim |
| --- | --- | --- | --- |
| Legacy UI proof of concept | Ubuntu Linux; external Expect script; Codex CLI 0.151.0; option 1 accepted harmless `curl -I https://example.com` network escalation | Historical proof only | Option 1 worked in that exact test; numeric ordering is not a supported interface |
| Hook protocol documentation | Current official OpenAI documentation describes `PermissionRequest`, structured allow/deny, no-decision flow, input fields, and hook configuration | Documented behavior, not version-specific proof | The project follows the documented shape, subject to release validation |
| Codex CLI 0.151.0 + Linux + local CLI launcher | Second isolated live end-to-end verification produced one real `PermissionRequest`, one structured allow response, completed the exact harmless curl request with HTTP/2 200, showed no interactive approval prompt, and left the temporary repository clean with temporary state cleaned up | **Verified** | The production registry admits exactly Codex 0.151.0, Linux, local CLI launcher, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Production compatibility registry | Typed entry in `src/compatibility.rs`, release `0.1.0` | **Verified, narrow scope** | `run`, `diagnose`, and `print-hook-config` use all runtime tuple checks before arming or printing |
| Linux launcher mechanics | Ordinary inherited child I/O, exact argument/exit forwarding, child-only environment, recursion protection, and fake-Codex tests | Verified for launcher mechanics | This does not expand Codex-version or surface compatibility |
| Isolated local hook verification path | Interactive, exact-version, temporary-repository, child-local-hook experiment | Experimental verification mechanism | It is not automatic promotion and must not be rerun for this milestone |
| macOS, Windows, and other operating systems | No independent compatibility evidence | Unsupported/unverified | No automatic decision |
| VS Code/IDE, desktop app, remote, container, WSL, SSH-hosted IDE, and Codex cloud surfaces | No independent compatibility evidence or secure arming design | Unsupported/unverified | No automatic decision |

## Rules for adding support

A Codex version requires exact version identification, a safe local PermissionRequest invocation, captured positive and negative fixtures, response and no-decision validation, concurrency/error review, and documentation updates. A feature flag or similar UI is not enough.

The experimental verifier is deliberately narrower than support promotion: it accepts only the exact local target `0.151.0`, requires interactive confirmation, uses a temporary repository and child-local override, and does not change the production allowlist. Promotion was based on the reviewed second run's hook invocation, exact response, harmless command result, absent approval prompt, clean repository, cleanup, and persistent-configuration invariants. The evidence is recorded without authentication material, environment contents, temporary directory names, session identifiers, or Cloudflare identifiers.

The registry records the hook event, project protocol/schema marker, observed tool type, response behavior, verification status and method, autoapprover release, and a concise evidence summary so future entries can expand independently across versions, operating systems, CLI/IDE surfaces, protocol versions, and autoapprover releases.

Compatibility with one Codex release never implies compatibility with a later release. Every version other than exactly 0.151.0, every platform other than Linux, and every surface other than the local CLI launched through `codex-autoapprover` is unsupported and unverified.

An operating system requires process-resolution, inherited terminal I/O, environment, interruption, exit-status, packaging, and recovery tests on that platform. The Ubuntu UI proof does not establish hook or cross-platform support.
