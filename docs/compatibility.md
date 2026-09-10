# Compatibility matrix

This matrix distinguishes reviewed production compatibility from the experimental verification mechanism and historical UI evidence. Compatibility is an exact tuple, not a version-only claim.

| Compatibility area | Evidence | Status | Supported claim |
| --- | --- | --- | --- |
| Legacy UI proof of concept | Ubuntu Linux; external Expect script; Codex CLI 0.151.0; option 1 accepted harmless `curl -I https://example.com` network escalation | Historical proof only | Option 1 worked in that exact test; numeric ordering is not a supported interface |
| Hook protocol documentation | Current official OpenAI documentation describes `PermissionRequest`, structured allow/deny, no-decision flow, input fields, and hook configuration | Documented behavior, not version-specific proof | The project follows the documented shape, subject to release validation |
| Codex CLI 0.151.0 + Linux + local CLI launcher | Second isolated live end-to-end verification produced one real `PermissionRequest`, one structured allow response, completed the exact harmless curl request with HTTP/2 200, showed no interactive approval prompt, and left the temporary repository clean with temporary state cleaned up | **Verified** | The production registry admits exactly Codex 0.151.0, Linux, local CLI launcher, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Codex CLI 0.153.0 + Linux + local CLI launcher | Installed target was inspected and its child-local configuration/features probes were successful, but no independently identifiable reviewed live evidence is retained in this checkout | **Experimental/unverified** | Automatic mode may attempt it after a passing non-live capability probe; strict mode leaves it unarmed; no live protocol verification or promotion is claimed |
| Codex CLI 0.153.4 + Linux + local CLI launcher | User-requested target; stable-version eligibility and non-live child-local hook/configuration capability probe only | **Experimental/unverified** | Automatic mode may attempt it after a passing capability probe; no live protocol verification or promotion is claimed |
| Codex CLI 0.154.0 + native Windows + local CLI launcher | User-requested target; stable-version eligibility and non-live child-local hook/configuration capability probe only | **Experimental/unverified** | Automatic mode may attempt it after a passing capability probe; no live protocol verification or promotion is claimed |
| Production compatibility registry | Typed entries in `src/compatibility.rs`, release `0.1.0`; Linux 0.151.0 and native Windows 0.153.2 are the reviewed live-verified tuples in this checkout | **Verified, narrow scope** | `run`, `diagnose`, and `print-hook-config` use separate eligibility, capability, schema, review, and arming gates |
| Automatic compatibility policy | Native Linux baseline Codex 0.153.0; native Windows baseline Codex 0.152.1; stable three-component versions at or above the matching baseline may be attempted after a passing non-live capability probe | **Experimental by default** | Newer does not mean verified; explicit exclusions, malformed/prerelease versions, unsupported surfaces/platforms, and inconclusive probes remain unarmed |
| Strict compatibility policy | `--compatibility strict` or `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` | **Exact reviewed tuples only** | Command-line mode takes precedence over the environment; arguments after `--` are always Codex arguments |
| Explicit incompatible exclusions | Typed `KNOWN_INCOMPATIBLE_EXCLUSIONS` registry, currently native Windows/local CLI Codex 0.152.0 below the inspected adapter baseline | **Unarmed** | Exclusions are explicit policy guards and are not claims of live protocol testing |
| Linux launcher mechanics | Ordinary inherited child I/O, exact argument/exit forwarding, child-only environment, recursion protection, and fake-Codex tests | Verified for launcher mechanics | This does not expand Codex-version or surface compatibility |
| Linux v1 process/session binding | Deterministic `/proc` parser/ancestry tests and fake-Codex broker path; exact child identity is `(PID, start time, effective UID)` | Implemented, security review pending | Unrelated, stale, mismatched-UID, PID-reused, malformed, or shutdown clients receive no decision |
| Isolated local hook verification path | Interactive, resolved-target, temporary-repository, child-local-hook experiment | Experimental verification mechanism | It is not automatic promotion; run manually only with the exact target instructions and review the redacted evidence |
| Codex CLI 0.152.1 + native Windows + local CLI launcher | Implementation and synthetic tests only; no reviewed live verification evidence yet | **Candidate/unverified** | Automatic `run` may attempt it after a passing non-live capability probe; strict mode leaves it unarmed; `verify-local-hook` may arm only after explicit interactive confirmation |
| Codex CLI 0.153.2 + native Windows + local CLI launcher | User-supplied live verification: one executable hook entry, one validated `PermissionRequest`, one exact `curl.exe -I https://example.com` match, one broker allow with one acknowledged response, one structured allow emission, stdout written once, HTTP 200, no manual approval prompt in the supplied transcript, child exit 0, clean temporary repository before and after, cleanup completed, verifier exit 0, first broker rejection none, and zero broker no-decision/errors or rejection counters | **Verified** | The exact tuple admits native Windows, local CLI launcher, Codex CLI 0.153.2, `PermissionRequest`, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Windows v1 process/session binding | Committed `731c0d8`/`9100596` implementation: `PIPE_REJECT_REMOTE_CLIENTS`, current-user DACL, `GetNamedPipeClientProcessId`, validated binary SID/`EqualSid`, Toolhelp ancestry using `(PID, creation time, user SID)`, overlapped I/O/cancellation, and the reconciled response-delivery regression test | Implemented; live tuple verified only as above | Unrelated, stale, mismatched-SID, PID-reused, malformed, or shutdown clients receive no decision; this does not broaden the 0.153.2 tuple |
| VS Code/IDE, desktop app, remote, container, WSL, SSH-hosted IDE, and Codex cloud surfaces | No independent compatibility evidence or secure arming design | Unsupported/unverified | No automatic decision |

## User-supplied native Windows evidence

The 0.153.2 live result above was supplied by the user from a native Windows terminal using Codex CLI 0.153.2. It was not rerun or independently captured in this checkout. No timestamp, raw audit artifact, or configuration-hash check was supplied, so none is claimed here. The displayed and verified probe was `curl.exe -I https://example.com`; the recorded counters were the redacted values in the matrix row. This evidence is limited to the exact tuple and does not promote Windows 0.152.1, Windows 0.154.0, other platforms, or other surfaces.

The implementation was tested while uncommitted on top of base commit `ee3c11c08ea9cf6ee3ace01eb7a01357b91693d5`. The following Git blob IDs tie the supplied result to the implementation and tests present before registry promotion:

| File | Git blob ID |
| --- | --- |
| `src/compatibility.rs` | `cc07debe6ff890e948ff9528d2be3652cc661c51` |
| `src/audit.rs` | `2c79168607498fa986ddcd43831d6a2101064561` |
| `src/bin/fake_codex.rs` | `08b2dfb0ad1f5df4495b70b6ecd10cfb3481267a` |
| `src/broker/windows.rs` | `ecd0012c0468a69d8c7d523b2287802d48c05155` |
| `src/codex.rs` | `8018385cbe000973f12fde1d4055739321ff2b33` |
| `src/decision.rs` | `eed5b9e620f3c7a192fc6cdf65441ae44b21efaa` |
| `src/hook.rs` | `21af8cb7594d0d4ea0594d1e99b3bd25ce5cd346` |
| `src/launcher.rs` | `40589114ca69ac7a2e11cf807b107427cfbfcd0e` |
| `tests/hook_mvp.rs` | `93f00886e3d3e7ea5ac777536e374fce3e60c41b` |

## Rules for adding support

A Codex version requires exact version identification, a safe local PermissionRequest invocation, captured positive and negative fixtures, response and no-decision validation, concurrency/error review, and documentation updates. A feature flag or similar UI is not enough.

The experimental verifier is deliberately narrower than support promotion: it resolves the current installed eligible stable target, requires interactive confirmation, uses a temporary repository and child-local override, and does not change the production allowlist. Linux authorizes only `curl -I https://example.com`; native Windows authorizes only `curl.exe -I https://example.com`. Evidence requires redacted exact-request hash evidence, structured allow emission, the successful child result used as command-result evidence, absent approval prompt, clean repository before and after, child exit, cleanup, and persistent-configuration invariants. Zero PermissionRequest invocations are inconclusive. The evidence is recorded without authentication material, environment contents, temporary directory names, session identifiers, or Cloudflare identifiers.

The registry records the hook event, project protocol/schema marker, observed tool type, response behavior, verification status and method, autoapprover release, and a concise evidence summary so future entries can expand independently across versions, operating systems, CLI/IDE surfaces, protocol versions, and autoapprover releases.

The internal binding protocol is `permission-binding-v1`; it is distinct from Codex's observed `permission-request-v1` hook protocol. It uses a length-prefixed JSON envelope with a maximum request of 1 MiB plus 4 KiB, a 256-byte response maximum, one request per connection, a two-second connection read/write timeout, and a maximum of 16 active connections. Native Windows uses event-backed overlapped pipe I/O with `CancelIoEx` on timeout/shutdown. No credential, environment, authentication material, or arbitrary file content is sent.

Compatibility with one Codex release never implies live verification of another release. Automatic mode attempts only stable native Linux/Windows local-CLI versions at or above the inspected adapter baseline after capability detection; every such newer release remains experimental/unverified until separately reviewed. Other platforms and all IDE, desktop, remote, container, WSL, SSH-hosted IDE, and cloud surfaces are unsupported and unarmed.

An operating system requires process-resolution, inherited terminal I/O, environment, interruption, exit-status, packaging, and recovery tests on that platform. The Ubuntu UI proof does not establish hook or cross-platform support.
