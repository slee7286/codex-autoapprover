# Security policy

## Scope and warning

`codex-autoapprover` can cause the official Codex CLI to receive an `allow` decision for a permission request. That may grant an individual command additional filesystem, network, Git, shell, or other authority. The hook does not make unconditional approval safe and does not strengthen Codex's sandbox.

The project is pre-alpha. Only Linux/local CLI/Codex 0.151.0 has a historical reviewed hook entry. The current implementation is not production-qualified. Windows 0.156.0 and all other unreviewed targets remain unarmed. The release policy blocks production qualification until the complete native matrix, binary identity binding, independent review and distribution requirements are met. See [production plan](docs/production-plan.md).

## Hook-specific attack surface

The security-sensitive boundary includes the hook's stdin JSON, its stdout protocol response, the inherited socket location and session secret, the resolved `codex` executable, hook configuration, child-process ancestry, the private runtime directory, and local audit output. Relevant failure sources include:

- malicious hook input, malformed JSON, oversized input, or unsupported schema changes;
- malicious repository content and prompt injection that influence a permission request;
- untrusted commands or descendants inheriting the arming environment variables;
- cross-session leakage or confusion between concurrent Codex sessions;
- `PATH` substitution or launching a malicious `codex` executable;
- tampered hook configuration or symlinked configuration/log paths;
- allowing the wrong hook event;
- returning permanent or session-wide authority instead of one-request authority;
- logs leaking commands, tool input, credentials, or other secrets; and
- installer or update-channel compromise.

The experimental `verify-local-hook` path requires a separate file-backed test login home and refuses the live/default Codex home. It copies only bounded private authentication bytes into a private temporary child home, clears inherited auth/state/startup overrides, uses normal hook trust, and retains a temporary redacted audit. It must not write live `config.toml` or install a persistent hook. Managed authentication requirements and hooks may still apply; this diagnostic cannot prove complete hook isolation. A successful network command with zero observed PermissionRequest invocations is inconclusive, and no compatibility entry may be promoted automatically.

The hook must be treated as a security-sensitive command that receives untrusted structured data. Textual or structured input is not proof that the request is safe or that the model's intent is benign.

The launcher keeps five security-relevant facts distinct: version/platform eligibility to attempt, detected hook/configuration capability, the supported runtime request schema, reviewed live-verification status, and active session arming. Passing one does not imply the others. A non-live help/feature probe only establishes that an attempt is possible; it does not verify the live PermissionRequest exchange.

## Required security properties

General arming and broker decisions require exact reviewed version/OS compatibility. The old automatic option is a strict alias; no configuration probe or unknown stable release may broaden support. Unsupported runtime requests produce no decision. The isolated verifier may use candidate schemas only when the broker also fixes the exact harmless probe and tool. It cannot authorize general commands.

The implementation must return only a one-request decision, never persistent or session-wide authority. Malformed/duplicate/oversized input, missing arming, wrong identity, mismatched cwd, unsupported schemas and internal errors must decline. Manual launch clears inherited broker credentials. Normal run never changes persistent Codex configuration. Windows sandbox repair is an explicit installer option with a backup; it does not certify compatibility.

Update detection only creates unverified candidate metadata and draft PRs. The prepared repair worker runs once after a failed candidate check, with a dedicated repair API key and a read-only repository token. It can emit only a bounded Rust source/test patch. A separate write-token job validates the patch without executing it; later Linux and Windows jobs rerun non-live checks with read-only tokens. The worker has no signing authority, cannot promote its own evidence or change the compatibility manifest, and cannot merge. This workflow is unactivated and untested on native CI; a dedicated low-privilege key, branch protections, independent review and live evidence remain required. Production readiness requires fresh code-bound native evidence and independent review; the local JSON gate checks integrity, not the truth of test claims. Repository protections must be activated separately.

The Linux v1 path creates a unique 0700 private runtime directory and 0600 Unix socket for each launch. The listener starts before Codex; after spawn the launcher records the exact child PID, `/proc/<pid>/stat` start time, and effective UID. For every connection, the broker obtains peer PID/UID/GID through Linux `SO_PEERCRED`, requires the peer UID to equal the launcher's effective UID, and traverses bounded `/proc` ancestry. The exact PID and start time must appear in two stable ancestry reads; loops, missing processes, malformed data, PID reuse, races, and depth exhaustion decline.

The secret remains defense in depth and is compared in a fixed-length byte loop. It is never sufficient by itself. Descendant processes can still inherit the socket location and secret, invoke the hook binary, or cause denial of service. This design meaningfully improves on inherited environment metadata alone but does not create a privilege boundary against malicious code already executing as the same user inside the exact authorized Codex descendant tree.

Native Windows uses a launcher-owned named pipe with remote-client rejection, current-user security, client process identity, user-SID and ancestry validation, bounded framed I/O, deadlines, and a response-delivery regression test. That is implementation evidence, not live Windows Codex verification; native Windows execution and live protocol behavior still require separate reproduction and review.

The verification hook additionally restricts the synthetic test to a `tool_input.command` equal to the platform-resolved nonce-bound `curl` (`curl.exe` on Windows) HEAD request to its local loopback witness. This is project-side fail-closed policy, not a claim that every Codex tool schema uses that field. If the real request does not expose that exact shape, verification declines and must not retry with a broader rule. Evidence must be redacted and must include the actual request hash match, structured allow emission, independently observed command outcome, clean pre/post repository state, child exit, and cleanup. A successful Codex child exit alone is not independent command-outcome evidence.

## Reporting a vulnerability

Use GitHub private vulnerability reporting or security advisories when available. Report false-positive allows, cross-session approval, schema confusion, permanent-rule approval, executable substitution, configuration tampering, secret exposure, or terminal/process recovery issues privately.

Do not publicly disclose an exploitable approval-bypass issue before coordinated remediation. Include the project commit/version, Codex version, operating system, mode, sanitized input shape, and impact, but do not include credentials, tokens, full commands, or authentication files.

## Emergency disable and recovery

If automation behaves unexpectedly:

1. interrupt or terminate the `codex-autoapprover` process;
2. use ordinary `codex` without the launcher;
3. remove the launcher from the invocation path or disarm the session environment;
4. revoke unintended persistent Codex rules if a separate configuration already contained them;
5. preserve only redacted diagnostics, hashes, versions, timestamps, and relevant process information; and
6. report the issue privately.

For the isolated verification command, an incorrect phrase, EOF, non-interactive stdin, timeout, or Ctrl-C before launch must abort without starting Codex. During the child run, stop the child, use ordinary `codex`, preserve only redacted evidence, and verify that no persistent configuration or approval rule was created.

The launcher must not require changing live Codex authentication or sandbox configuration as an emergency step.

IDE-extension integration is not independently verified and is unsupported. A future IDE path must use a separately reviewed persistent-hook and secure arming design; the current CLI token/environment model must not be reused as if it proved IDE session identity.
