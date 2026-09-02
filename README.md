# codex-autoapprover

`codex-autoapprover` is an unofficial, independent launcher for a user's existing official Codex CLI. Its authoritative design uses Codex's structured `PermissionRequest` hook: an explicitly armed child process can return the documented one-request `allow` decision before Codex shows its normal approval prompt.

> **Security warning:** automatic approval can authorize filesystem, network, Git, shell, and other consequential actions. It does not make those actions safe, inspect their intent, or strengthen Codex's sandbox. Repeated one-request approvals can approach unrestricted practical authority over time.

This project is not affiliated with, endorsed by, sponsored by, or maintained by OpenAI.

## Status

The project is **pre-alpha**. Production automatic approval is verified only for Linux, the local CLI launcher surface, and Codex CLI 0.151.0. Native Windows with Codex CLI 0.152.1 is implemented and natively compiled/tested as a **candidate/unverified** tuple pending isolated live verification and manual evidence review. No live Codex configuration is installed or modified.

### Evidence and compatibility

The verified legacy proof of concept is limited to Ubuntu Linux, Codex CLI 0.151.0, an external Expect script, and option 1 producing one-time acceptance for the harmless command `curl -I https://example.com`. It is historical UI evidence only. OpenAI does not document numeric approval-option ordering as a stable interface, so option 1 is not a supported interface and the proof does not establish hook support for Codex 0.151.0 or any other version.

The reviewed second isolated live verification against the locally installed `codex-cli 0.151.0` produced one real `PermissionRequest`, one structured allow response, completed the exact harmless `curl -I https://example.com` request with HTTP/2 200, showed no interactive approval prompt, and ended with a clean temporary repository and cleaned temporary state. This evidence supports only the exact registry entry in [docs/compatibility.md](docs/compatibility.md).

## Intended behavior

- `codex` continues to start ordinary Codex with normal approval behavior.
- `codex-autoapprover run -- ...` resolves and starts the user's existing official `codex` executable with inherited terminal I/O and a launcher-owned per-invocation broker.
- Codex remains responsible for its normal TUI, authentication, configuration, sessions, model selection, sandbox, plugins, arguments, and exit behavior.
- For a version in the explicit verified allowlist, the launcher registers this executable as a synchronous `PermissionRequest` hook through a child-only Codex configuration override.
- The hook sends its bounded request to the broker. Only the broker can return the documented structured `allow` decision for the current request; it never returns a permanent or session-wide approval decision.
- Unarmed processes, unknown events, malformed input, unsupported versions, missing bindings, and internal failures produce no approval decision; Codex's normal approval flow remains in control.
- The launcher does not depend on approval option numbering, terminal wording, ANSI parsing, cursor position, or screen scraping.

Automatic approval is enabled only for the exact verified registry entry. Unknown or unverified versions, operating systems, hook protocols, tool types, and surfaces remain unarmed and preserve Codex's ordinary approval behavior.

## Commands

```text
codex-autoapprover run [-- <codex arguments...>]
codex-autoapprover hook
codex-autoapprover diagnose
codex-autoapprover print-hook-config
codex-autoapprover verify-local-hook
```

With no subcommand, the binary behaves as `run` with no Codex arguments. `hook` is a protocol entry point for Codex and must not be invoked as a general-purpose approval API. `print-hook-config` never writes configuration and refuses to print a support snippet for an unverified installed version.

`verify-local-hook` is a separate, experimental, interactive-only verification mechanism. On Linux it is limited to Codex 0.151.0 and requires `VERIFY CODEX 0.151.0 HOOK`. On native Windows it is limited to Codex 0.152.1 and requires `VERIFY CODEX 0.152.1 WINDOWS HOOK`. It uses a temporary Git repository and child-only `-c` overrides, does not promote compatibility, and must not be run automatically in CI.

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
- a typed compatibility registry with one reviewed Linux/local-CLI/Codex-0.151.0 entry;
- exact version, platform, surface, protocol, and `Bash` tool gating before child arming;
- Linux process/session binding: a 0700 private runtime directory, 0600 Unix socket, kernel peer credentials, and exact Codex PID plus `/proc` start-time ancestry validation;
- Windows process/session binding: a current-user-only named-pipe DACL, remote-client rejection, kernel peer PID, native binary SID equality, process creation time, and two stable bounded Toolhelp ancestry walks;
- Windows overlapped named-pipe I/O with event waits, a two-second connection-decision deadline, `CancelIoEx` cancellation, and deterministic handle cleanup;
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

These commands do not install hooks, modify `~/.codex`, or perform a real automatic escalation. `print-hook-config` succeeds only when the installed target exactly matches the verified Linux local-CLI entry.

After implementation and synthetic checks have been reviewed, a user at a real interactive terminal may explicitly start the isolated experiment with `cargo run -- verify-local-hook`. The command requests the exact generated confirmation phrase immediately before launching Codex. It is not part of `cargo test` and must not be automated.

Installation packages are not available. Do not treat an ad hoc build as a supported installer or release.

## Roadmap

1. Complete an independent security review of the Linux binding and its same-user threat boundary.
2. Complete Linux beta tests for launcher inheritance, hook protocol, concurrency, and recovery.
3. Design a safe, explicit configuration installer and uninstaller without changing Codex authentication or approval rules.
4. Design and independently verify an IDE extension path with persistent-hook isolation and secure arming.
5. Assess macOS and Windows process/terminal compatibility.
6. Consider a structured Codex App Server backend if its approval protocol is stable and documented.

Compatibility with Codex 0.151.0 does not imply compatibility with later or earlier releases. Every other Codex version, macOS, Windows, other operating systems, VS Code/IDE surfaces, desktop app, remote, container, WSL, SSH-hosted IDE, and Codex cloud surface is unsupported and unverified.

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
