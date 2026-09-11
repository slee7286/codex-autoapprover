# Compatibility matrix

This matrix distinguishes reviewed production compatibility from the experimental verification mechanism and historical UI evidence. Compatibility is an exact tuple, not a version-only claim.

## Release-manifest compatibility metadata

M1-T1 defines the descriptive release-manifest schema implemented in
src/update/manifest.rs. The canonical JSON uses schema version 1 and
snake_case field names. It contains bounded release metadata, HTTPS release
notes, native x86_64 asset records, proposed runtime requirements, archive
format, byte length, lowercase SHA-256 text, download origin, and build
provenance. Compatibility entries contain an exact Codex version, operating
system, architecture, launcher surface, hook event/protocol, required tool and
input schema, response behavior, and one of reviewed, experimental, or
excluded eligibility records.

Parsing rejects duplicate keys, unknown nested fields, duplicate asset or
compatibility identities, malformed stable versions, invalid lengths/hashes,
unsupported schema versions, and contradictory compatibility entries. Canonical
serialization sorts asset and compatibility arrays by identity. The proposed
Windows and Linux runtime floors remain unvalidated until the native M4/M6
acceptance work; synthetic fixtures do not promote compatibility.

This metadata is descriptive only. It cannot arm the broker, bypass runtime
identity/session/cwd/tool/schema/command checks, or promote an installed Codex
version to reviewed support. A parsed manifest is untrusted until a later TUF
adapter authenticates the exact target bytes and target length/hash using the
repository's selected TUF trust model. The schema contains no competing
signature format and does not implement signature verification or custom
cryptography; it only compares the parsed bytes with a TUF-supplied SHA-256
target digest. Selection, network fetching, persistent state, installation,
and startup prompting are later milestones.

M1-T2 selection consumes only a TUF-authenticated manifest wrapper and typed
installed-version/Codex/platform/architecture/runtime/surface/policy inputs.
It ranks all applicable candidates by numeric autoapprover release version and
rejects equal-release, conflicting-asset, overlapping-compatibility, and
equal-ranked-asset ambiguity. It never ranks by input order or publication
date. A newer incompatible release is skipped in favor of an older release
that is still newer than the installed version.

Under automatic mode, the newest applicable exact tuple may be reviewed or
explicitly experimental; the result retains its experimental label. Under
strict mode, experimental records are rejected and the newest applicable exact
reviewed tuple is selected instead. Therefore, when a newer experimental
release and an older reviewed release are both applicable, automatic mode
selects the newer experimental release while strict mode selects the older
reviewed release. Exact exclusions take precedence over any overlapping
experimental eligibility. Selection does not authorize downloading,
execution, activation, or broker decisions.

## M1-T3 metadata and authorization boundary

The update path has six deliberately separate stages:

1. Untrusted bytes are bounded input and have no metadata or compatibility
   authority.
2. `ParsedManifest` is a structurally validated, descriptive value. It has
   strict schema, duplicate, length, and hash-field checks, but it is not
   publisher authenticated.
3. `AuthenticatedManifest` is a verifier-owned, read-only wrapper. Its
   production constructor is intentionally absent until the future TUF
   verifier is implemented. The current `#[cfg(test)]` `synthetic_for_tests`
   constructor only checks that caller-supplied target name, length, and
   SHA-256 match the fixture bytes; it executes no TUF verification and is not
   publisher-authentication evidence.
4. Applicable-release selection accepts only that wrapper and typed runtime
   inputs. Selection preserves reviewed versus experimental status but cannot
   download, execute, install, activate, or authorize a hook.
5. User-approved installation is a later consent and activation stage. Its
   authenticated target must come from the repository's TUF chain; a matching
   hash/length or a parsed manifest alone is never an independent trust system.
6. Runtime Codex compatibility and broker authorization remain the existing
   authority. Metadata cannot arm a hook, edit the compiled reviewed registry,
   override strict mode/exclusions, broaden the exact command, or bypass
   version, schema, tool, cwd, secret, process-identity, ancestry, or session
   checks. Local success cannot promote project-wide reviewed support.

The wrapper is not deserializable or cloneable as a trusted value. Callers can
clone a read-only manifest view only as an ordinary descriptive copy; mutating
that copy does not mutate or retain the authenticated wrapper. No updater path
runs inside hook protocol execution or writes diagnostics to hook stdout.
Real TUF root/role/expiry/target verification remains deferred to M5-T2;
the boundary tests are synthetic type/byte-binding tests, not TUF
verification tests.

| Compatibility area | Evidence | Status | Supported claim |
| --- | --- | --- | --- |
| Legacy UI proof of concept | Ubuntu Linux; external Expect script; Codex CLI 0.151.0; option 1 accepted harmless `curl -I https://example.com` network escalation | Historical proof only | Option 1 worked in that exact test; numeric ordering is not a supported interface |
| Hook protocol documentation | Current official OpenAI documentation describes `PermissionRequest`, structured allow/deny, no-decision flow, input fields, and hook configuration | Documented behavior, not version-specific proof | The project follows the documented shape, subject to release validation |
| Codex CLI 0.151.0 + Linux + local CLI launcher | Second isolated live end-to-end verification produced one real `PermissionRequest`, one structured allow response, completed the exact harmless curl request with HTTP/2 200, showed no interactive approval prompt, and left the temporary repository clean with temporary state cleaned up | **Verified** | The production registry admits exactly Codex 0.151.0, Linux, local CLI launcher, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Codex CLI 0.153.0 + Linux + local CLI launcher | Installed target was inspected and its child-local configuration/features probes were successful, but no independently identifiable reviewed live evidence is retained in this checkout | **Experimental/unverified** | Automatic mode may attempt it after a passing non-live capability probe; strict mode leaves it unarmed; no live protocol verification or promotion is claimed |
| Codex CLI 0.153.4 + Linux + local CLI launcher | User-requested target; stable-version eligibility and non-live child-local hook/configuration capability probe only | **Experimental/unverified** | Automatic mode may attempt it after a passing capability probe; no live protocol verification or promotion is claimed |
| Codex CLI 0.154.0 + native Windows + local CLI launcher | User-supplied live verification: one executable hook entry, one validated `PermissionRequest`, one exact `curl.exe -I https://example.com` match, one allow record, one structured allow emission, one acknowledged broker response, stdout written once, HTTP 200, no manual approval prompt in the supplied transcript, child and verifier exit 0, clean temporary repository, successful cleanup, and zero broker errors, no-decision results, or rejection counters | **Verified** | The exact tuple admits native Windows, local CLI launcher, Codex CLI 0.154.0, `PermissionRequest`, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Production compatibility registry | Typed entries in `src/compatibility.rs`, release `0.1.0`; Linux 0.151.0 and native Windows 0.153.2/0.154.0 are the reviewed live-verified tuples in this checkout | **Verified, narrow scope** | `run`, `diagnose`, and `print-hook-config` use separate eligibility, capability, schema, review, and arming gates |
| Automatic compatibility policy | Native Linux baseline Codex 0.153.0; native Windows baseline Codex 0.152.1; stable three-component versions at or above the matching baseline may be attempted after a passing non-live capability probe | **Experimental by default** | Newer does not mean verified; explicit exclusions, malformed/prerelease versions, unsupported surfaces/platforms, and inconclusive probes remain unarmed |
| Strict compatibility policy | `--compatibility strict` or `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` | **Exact reviewed tuples only** | Command-line mode takes precedence over the environment; arguments after `--` are always Codex arguments |
| Explicit incompatible exclusions | Typed `KNOWN_INCOMPATIBLE_EXCLUSIONS` registry, currently native Windows/local CLI Codex 0.152.0 below the inspected adapter baseline | **Unarmed** | Exclusions are explicit policy guards and are not claims of live protocol testing |
| Linux launcher mechanics | Ordinary inherited child I/O, exact argument/exit forwarding, child-only environment, recursion protection, and fake-Codex tests | Verified for launcher mechanics | This does not expand Codex-version or surface compatibility |
| Linux v1 process/session binding | Deterministic `/proc` parser/ancestry tests and fake-Codex broker path; exact child identity is `(PID, start time, effective UID)` | Implemented, security review pending | Unrelated, stale, mismatched-UID, PID-reused, malformed, or shutdown clients receive no decision |
| Isolated local hook verification path | Interactive, resolved-target, temporary-repository, child-local-hook experiment | Experimental verification mechanism | It is not automatic promotion; run manually only with the exact target instructions and review the redacted evidence |
| Codex CLI 0.152.1 + native Windows + local CLI launcher | Implementation and synthetic tests only; no reviewed live verification evidence yet | **Candidate/unverified** | Automatic `run` may attempt it after a passing non-live capability probe; strict mode leaves it unarmed; `verify-local-hook` may arm only after explicit interactive confirmation |
| Codex CLI 0.153.2 + native Windows + local CLI launcher | User-supplied live verification: one executable hook entry, one validated `PermissionRequest`, one exact `curl.exe -I https://example.com` match, one broker allow with one acknowledged response, one structured allow emission, stdout written once, HTTP 200, no manual approval prompt in the supplied transcript, child exit 0, clean temporary repository before and after, cleanup completed, verifier exit 0, first broker rejection none, and zero broker no-decision/errors or rejection counters | **Verified** | The exact tuple admits native Windows, local CLI launcher, Codex CLI 0.153.2, `PermissionRequest`, `permission-request-v1`, observed `Bash`, and one-request structured allow |
| Windows v1 process/session binding | Committed `731c0d8`/`9100596` implementation: `PIPE_REJECT_REMOTE_CLIENTS`, current-user DACL, `GetNamedPipeClientProcessId`, validated binary SID/`EqualSid`, Toolhelp ancestry using `(PID, creation time, user SID)`, overlapped I/O/cancellation, and the reconciled response-delivery regression test | Implemented; live tuples verified only as above | Unrelated, stale, mismatched-SID, PID-reused, malformed, or shutdown clients receive no decision; this does not broaden either verified tuple |
| VS Code/IDE, desktop app, remote, container, WSL, SSH-hosted IDE, and Codex cloud surfaces | No independent compatibility evidence or secure arming design | Unsupported/unverified | No automatic decision |

## User-supplied native Windows evidence

The 0.153.2 live result above was supplied by the user from a native Windows terminal using Codex CLI 0.153.2. It was not rerun or independently captured in this checkout. No timestamp, raw audit artifact, or configuration-hash check was supplied, so none is claimed here. The displayed and verified probe was `curl.exe -I https://example.com`; the recorded counters were the redacted values in the matrix row. This evidence is limited to the exact tuple and does not promote Windows 0.152.1, other platforms, or other surfaces.

The 0.154.0 live result above was also supplied by the user from a native Windows terminal using Codex CLI 0.154.0. It was not performed by this agent. The tested implementation was commit `a328a8fbad5cd5595fabb723bc18bc0941b88894`; this is the full SHA corresponding to the supplied short reference `a328a8f`. The supplied excerpt did not include the pre-launch baseline output, and it mentioned one startup issue without its contents; neither is treated as evidence or diagnosed here. The exact `curl.exe -I https://example.com` line is recorded as the verifier probe evidence and does not add a new production command restriction. No timestamp, raw audit artifact, or configuration-hash check was supplied, so none is claimed. This evidence is limited to native Windows, the local CLI launcher, Codex CLI 0.154.0, and the existing hook tuple; it does not promote Windows 0.152.1, other platforms, or other surfaces.

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
