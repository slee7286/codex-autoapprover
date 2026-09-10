# codex-autoapprover

`codex-autoapprover` is an unofficial, independent launcher for a user's existing official Codex CLI. Its authoritative design uses Codex's structured `PermissionRequest` hook: an explicitly armed child process can return the documented one-request `allow` decision before Codex shows its normal approval prompt.

> **Security warning:** automatic approval can authorize filesystem, network, Git, shell, and other consequential actions. It does not make those actions safe, inspect their intent, or strengthen Codex's sandbox. Repeated one-request approvals can approach unrestricted practical authority over time.

This project is not affiliated with, endorsed by, sponsored by, or maintained by OpenAI.

## Status

The project is **pre-alpha**. Production automatic approval is verified only for Linux, the local CLI launcher surface, and Codex CLI 0.151.0. The installed Linux 0.153.0 target has no independently identifiable reviewed live evidence in this checkout and is therefore **experimental/unverified**. Native Windows with Codex CLI 0.152.1 is a **candidate/unverified** tuple pending isolated live verification. Linux 0.153.4 and native Windows 0.154.0 are explicit **experimental/unverified** requested targets. Newer stable versions at or above the inspected platform adapter baseline are attempted automatically only after a non-live capability check; they are never called verified because they are newer. No live Codex configuration is installed or modified.

### Evidence and compatibility

The verified legacy proof of concept is limited to Ubuntu Linux, Codex CLI 0.151.0, an external Expect script, and option 1 producing one-time acceptance for the harmless command `curl -I https://example.com`. It is historical UI evidence only. OpenAI does not document numeric approval-option ordering as a stable interface, so option 1 is not a supported interface and the proof does not establish hook support for Codex 0.151.0 or any other version.

The repository-recorded reviewed isolated live verification for Linux/Codex CLI 0.151.0 is retained from commit `4206097` and supports only that exact registry tuple. The later Linux 0.153.0 label was not backed by independently identifiable reviewed live evidence in this checkout; its local help/features observations and non-live probes are retained as capability evidence only, so 0.153.0 is experimental/unverified.

## Intended behavior

- `codex` continues to start ordinary Codex with normal approval behavior.
- `codex-autoapprover run -- ...` resolves and starts the user's existing official `codex` executable with inherited terminal I/O and a launcher-owned per-invocation broker.
- Codex remains responsible for its normal TUI, authentication, configuration, sessions, model selection, sandbox, plugins, arguments, and exit behavior.
- For an exact verified tuple, or for an eligible newer stable version whose child-local hook configuration passes the capability probe, the launcher registers this executable as a synchronous `PermissionRequest` hook through a child-only Codex configuration override.
- The hook sends its bounded request to the broker. Only the broker can return the documented structured `allow` decision for the current request; it never returns a permanent or session-wide approval decision.
- Unarmed processes, unknown events, malformed input, unsupported versions, missing bindings, and internal failures produce no approval decision; Codex's normal approval flow remains in control.
- The launcher does not depend on approval option numbering, terminal wording, ANSI parsing, cursor position, or screen scraping.

Automatic compatibility attempts are the default on implemented native Linux and native Windows local-CLI surfaces. Strict mode restores exact reviewed-tuple-only arming. Unknown, malformed, prerelease, explicitly excluded, unsupported-platform, unsupported-surface, unsupported-schema, and capability-inconclusive targets remain unarmed and preserve Codex's ordinary approval behavior. Runtime rejection likewise returns no decision, so Codex's normal approval flow remains in control. Protocol validation makes the adapter fail closed; it does not make arbitrary automatically approved commands safe.

## Commands

```text
codex-autoapprover run [-- <codex arguments...>]
codex-autoapprover run [--compatibility automatic|strict] -- <codex arguments...>
codex-autoapprover hook
codex-autoapprover diagnose
codex-autoapprover print-hook-config
codex-autoapprover verify-local-hook
```

With no subcommand, the binary behaves as `run` with no Codex arguments. `hook` is a protocol entry point for Codex and must not be invoked as a general-purpose approval API. `--compatibility` belongs before the `--` separator; every argument after `--` is forwarded to Codex unchanged. `CODEX_AUTOAPPROVER_COMPATIBILITY=automatic|strict` selects the default when the flag is absent, and the command-line flag takes precedence. `print-hook-config` never writes configuration and refuses to print a support snippet for an unverified installed version.

`verify-local-hook` is a separate, experimental, interactive-only verification mechanism. It resolves the installed eligible stable version into one verification target, then derives the displayed command, confirmation phrase, child version binding, prompt, and broker authorization from that target. Linux uses `curl -I https://example.com`; native Windows uses `curl.exe -I https://example.com`. For example, the current Linux target requires `VERIFY CODEX 0.153.0 HOOK`, while the requested Windows target would require `VERIFY CODEX 0.154.0 WINDOWS HOOK`. It uses a temporary Git repository and child-only `-c` overrides, does not promote compatibility, and must not be run automatically in CI.

## Implemented and unimplemented

Implemented in this milestone:

- CLI parsing for the five commands;
- official `codex` path resolution with recursive self-resolution protection;
- inherited stdin, stdout, and stderr child launch;
- Codex argument forwarding and exit-status propagation;
- launcher-owned per-invocation broker secret and cwd policy binding;
- bounded JSON parsing and exact documented allow-response serialization;
- fail-closed handling for unarmed, malformed, unknown, and mismatched requests;
- non-sensitive diagnostics and synthetic protocol/launcher tests;
- a typed compatibility registry with the reviewed Linux/local-CLI Codex 0.151.0 entry, an explicitly unverified inspected Linux 0.153.0 entry, a Windows candidate, and the requested experimental targets Linux 0.153.4 and Windows 0.154.0;
- separate version eligibility, non-live hook/configuration capability detection, runtime request-schema validation, reviewed live-verification status, and active-session arming gates;
- automatic attempts for newer stable releases at or above the platform adapter baseline, plus `--compatibility strict` and `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` exact-tuple opt-in;
- exact version, platform, surface, protocol, and `Bash` tool gating before child arming;
- Linux process/session binding: a 0700 private runtime directory, 0600 Unix socket, kernel peer credentials, and exact Codex PID plus `/proc` start-time ancestry validation;
- Windows process/session binding: a current-user-only named-pipe DACL, remote-client rejection, kernel peer PID, native binary SID equality, process creation time, and two stable bounded Toolhelp ancestry walks;
- Windows overlapped named-pipe I/O with event waits, a two-second connection-decision deadline, `CancelIoEx` cancellation, complete response-delivery coverage, and deterministic handle cleanup;
- native Windows fake-Codex coverage for `.exe`, npm `.cmd`, and PowerShell `.ps1` launchers, including paths with spaces/non-ASCII characters and shell metacharacters;
- bounded, versioned broker framing, timeouts, resource limits, and shutdown cleanup;

Not implemented or not verified:

- automatic installation, updating, or removal of live Codex hook configuration;
- IDE-extension integration, including its separate persistent-hook and secure-arming design;
- a permanent configuration/rules mode;
- packages or a supported release; and
- a direct App Server backend.

The native Windows preflight used Rust/MSVC on Windows 11 with `codex-cli 0.152.1`. A first isolated live attempt then failed safely because its generated prompt used bare `curl`, which PowerShell resolved to `Invoke-WebRequest` instead of the authorized `curl.exe`; it produced zero hook invocations and zero allows, changed no persistent configuration, and supplied no positive compatibility evidence. Windows 0.152.1 remains candidate/unverified and was not promoted.

The arming secret remains inherited by descendants as defense in depth. It is no longer sufficient for approval: the broker also requires kernel peer credentials and exact live ancestry. This is not perfect same-user isolation.

Planned operating modes are `off/manual`, `observe`, `accept-once`, and a future `scoped/rules-based` mode. The current production path is a verified, child-local `accept-once` hook for one exact target; repeated requests in an armed session remain individually consequential.

## Development

Prerequisites are Rust edition 2024 and the dependencies declared in [Cargo.toml](Cargo.toml). The runtime uses `clap`, `getrandom`, `rustix` (minimal `net`, `process`, and `std` features for Linux peer credentials and effective UID), `serde`, `serde_json`, `sha2`, `signal-hook`, `tempfile`, `thiserror`, and `which`; test support uses `assert_cmd` and `predicates`.

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo build
cargo run -- diagnose
cargo run -- print-hook-config
```

These commands do not install hooks, modify `~/.codex`, or perform a real automatic escalation. `diagnose` may run bounded, non-live Codex help/feature capability probes. `print-hook-config` succeeds only when the installed target exactly matches a verified local-CLI entry.

After implementation and synthetic checks have been reviewed, a user at a real interactive terminal may explicitly start the isolated experiment with `cargo run -- verify-local-hook`. The command requests the exact generated confirmation phrase immediately before launching Codex. It is not part of `cargo test` and must not be automated.

Installation packages are not available. Do not treat an ad hoc build as a supported installer or release.

## Roadmap

1. Complete an independent security review of the Linux binding and its same-user threat boundary.
2. Complete Linux beta tests for launcher inheritance, hook protocol, concurrency, and recovery.
3. Design a safe, explicit configuration installer and uninstaller without changing Codex authentication or approval rules.
4. Design and independently verify an IDE extension path with persistent-hook isolation and secure arming.
5. Assess macOS and Windows process/terminal compatibility.
6. Consider a structured Codex App Server backend if its approval protocol is stable and documented.

Verified compatibility with Codex 0.151.0 does not imply live verification of another release. Automatic attempts cover only stable native Linux/Windows local-CLI versions at or above the inspected adapter baseline and a passing child-local capability probe. macOS, other operating systems, VS Code/IDE surfaces, desktop app, remote, container, WSL, SSH-hosted IDE, and Codex cloud remain unsupported and unarmed.

## Documentation

- [Security policy](SECURITY.md)
- [Product contract](docs/product-contract.md)
- [Threat model](docs/threat-model.md)
- [Proposed architecture](docs/architecture.md)
- [Hook protocol](docs/hook-protocol.md)
- [Compatibility matrix](docs/compatibility.md)

## Licence

This project is licensed under the [MIT License](LICENSE).

## Trademark notice

“Codex” and “OpenAI” are names or marks associated with OpenAI. They are used only to describe compatibility with a user's existing official Codex CLI. This independent project does not imply affiliation, endorsement, sponsorship, or maintenance by OpenAI.
