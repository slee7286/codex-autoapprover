# Security policy

## Scope and warning

`codex-autoapprover` can cause the official Codex CLI to receive an `allow` decision for a permission request. That may grant an individual command additional filesystem, network, Git, shell, or other authority. The hook does not make unconditional approval safe and does not strengthen Codex's sandbox.

The project is pre-alpha. The only narrowly verified production compatibility is Linux, the local CLI launcher, and Codex CLI 0.151.0. This does not constitute support for any other version, platform, or surface.

## Hook-specific attack surface

The security-sensitive boundary includes the hook's stdin JSON, its stdout protocol response, inherited environment variables, the resolved `codex` executable, hook configuration, child-process ancestry, and local audit output. Relevant failure sources include:

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

The experimental `verify-local-hook` path adds a temporary repository, inherited official authentication, a child-local `-c` hook override, an exact confirmation phrase, and a temporary redacted audit file. It must not write `~/.codex/config.toml` or install a persistent hook. Its one-off hook-trust bypass is not a sandbox or approval bypass; other configured hooks may still participate according to Codex's normal composition.

The hook must be treated as a security-sensitive command that receives untrusted structured data. Textual or structured input is not proof that the request is safe or that the model's intent is benign.

## Required security properties

The implementation must fail closed on unknown events, malformed input, unsupported versions or schemas, missing arming, binding mismatch, and internal errors. It must emit no unrelated stdout because stdout is protocol-sensitive, and it must return only the exact documented one-request `allow` object when all checks succeed.

The implementation must never return a permanent or session-wide approval. It must use an explicit version allowlist, require explicit per-session arming, avoid a constant boolean arming flag, avoid full command logging by default, and provide an emergency disable path. It must not silently fall back to permissive behavior.

The first MVP uses a cryptographically random child-session token, exact verified Codex version/protocol/surface metadata, observed `Bash` tool gating, and expected cwd. Descendant processes can inherit the arming values and may be able to invoke the hook with synthetic input; this is a known limitation and must be mitigated with stronger process/session binding before public release.

This milestone does not add Linux `/proc` ancestry binding. A candidate design is to record the expected Codex child PID and process start time in a 0700 `$XDG_RUNTIME_DIR` session directory, then require a hook-side ancestry check before allowing. PID reuse, hook process ancestry, races during spawn, and descendant inheritance require dedicated testing before that design can replace the current checks.

The verification hook additionally restricts the synthetic test to a `tool_input.command` equal to `curl -I https://example.com`. This is project-side fail-closed policy, not a claim that every Codex tool schema uses that field. If the real request does not expose that exact shape, verification declines and must not retry with a broader rule.

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
