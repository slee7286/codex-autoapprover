# Security policy

## Scope and warning

`codex-autoapprover` can cause the official Codex CLI to receive an `allow` decision for a permission request. That may grant an individual command additional filesystem, network, Git, shell, or other authority. The hook does not make unconditional approval safe and does not strengthen Codex's sandbox.

The project is pre-alpha. The narrowly verified production compatibility is Linux, the local CLI launcher, and Codex CLI 0.151.0. Linux 0.153.0 has no independently identifiable reviewed live evidence in this checkout and remains experimental/unverified; native Windows 0.152.1 is candidate/unverified; Linux 0.153.4 and native Windows 0.154.0 are experimental/unverified requested targets. Automatic attempts on newer stable versions are compatibility experiments, not verification or a safety guarantee.

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

The experimental `verify-local-hook` path adds a temporary repository, inherited official authentication, a child-local `-c` hook override, an exact confirmation phrase derived from the resolved target, and a temporary redacted audit file. It must not write `~/.codex/config.toml` or install a persistent hook. Its one-off hook-trust bypass is not a sandbox or approval bypass; other configured hooks may still participate according to Codex's normal composition. A successful network command with zero observed PermissionRequest invocations is inconclusive, not successful verification, and no compatibility entry may be promoted automatically.

The hook must be treated as a security-sensitive command that receives untrusted structured data. Textual or structured input is not proof that the request is safe or that the model's intent is benign.

The launcher keeps five security-relevant facts distinct: version/platform eligibility to attempt, detected hook/configuration capability, the supported runtime request schema, reviewed live-verification status, and active session arming. Passing one does not imply the others. A non-live help/feature probe only establishes that an attempt is possible; it does not verify the live PermissionRequest exchange.

## Required security properties

The implementation must fail closed on unknown events, malformed input, unknown or prerelease version strings, unsupported versions or schemas, missing arming, binding mismatch, capability-probe failure, and internal errors. Automatic mode may attempt eligible newer stable versions, but strict mode (`--compatibility strict` or `CODEX_AUTOAPPROVER_COMPATIBILITY=strict`) may arm only reviewed exact tuples. Before arming an experimental target it must print:

> Experimental automatic approvals: Codex VERSION on PLATFORM has not been live-verified. Eligible permission requests will be approved automatically; incompatible requests fall back to normal approval.

The warning must be accompanied by a clear compatibility and command-execution risk warning. It must emit no unrelated stdout because stdout is protocol-sensitive, and it must return only the exact documented one-request `allow` object when all checks succeed. An ineligible, incompatible, malformed, or rejected request receives no decision and therefore follows Codex's normal approval behavior.

The implementation must never return a permanent or session-wide approval. It must use an explicit platform/adapter baseline, a maintained known-incompatible exclusion list, and strict exact-tuple review metadata; require explicit per-session arming; avoid a constant boolean arming flag; avoid full command logging by default; and provide an emergency disable path. It must not silently fall back to permissive behavior.

The Linux v1 path creates a unique 0700 private runtime directory and 0600 Unix socket for each launch. The listener starts before Codex; after spawn the launcher records the exact child PID, `/proc/<pid>/stat` start time, and effective UID. For every connection, the broker obtains peer PID/UID/GID through Linux `SO_PEERCRED`, requires the peer UID to equal the launcher's effective UID, and traverses bounded `/proc` ancestry. The exact PID and start time must appear in two stable ancestry reads; loops, missing processes, malformed data, PID reuse, races, and depth exhaustion decline.

The secret remains defense in depth and is compared in a fixed-length byte loop. It is never sufficient by itself. Descendant processes can still inherit the socket location and secret, invoke the hook binary, or cause denial of service. This design meaningfully improves on inherited environment metadata alone but does not create a privilege boundary against malicious code already executing as the same user inside the exact authorized Codex descendant tree.

Native Windows uses a launcher-owned named pipe with remote-client rejection, current-user security, client process identity, user-SID and ancestry validation, bounded framed I/O, deadlines, and a response-delivery regression test. That is implementation evidence, not live Windows Codex verification; native Windows execution and live protocol behavior still require separate reproduction and review.

The verification hook additionally restricts the synthetic test to a `tool_input.command` equal to the platform-resolved exact command: `curl -I https://example.com` on Linux and `curl.exe -I https://example.com` on native Windows. This is project-side fail-closed policy, not a claim that every Codex tool schema uses that field. If the real request does not expose that exact shape, verification declines and must not retry with a broader rule. Evidence must be redacted and must include the actual request hash match, structured allow emission, the successful child result used as command-result evidence, clean pre/post repository state, child exit, and cleanup.

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
