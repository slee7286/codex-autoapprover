# codex-autoapprover

`codex-autoapprover` is an unofficial, independent launcher for a user's existing official Codex CLI. Its authoritative design uses Codex's structured `PermissionRequest` hook: an explicitly armed child process can return the documented one-request `allow` decision before Codex shows its normal approval prompt.

> **Security warning:** automatic approval can authorize filesystem, network, Git, shell, and other consequential actions. It does not make those actions safe, inspect their intent, or strengthen Codex's sandbox. Repeated one-request approvals can approach unrestricted practical authority over time.

This project is not affiliated with, endorsed by, sponsored by, or maintained by OpenAI.

## Status

The project is **pre-alpha**. The only production compatibility entry is narrowly verified for Linux, the local CLI launcher surface, and Codex CLI 0.151.0. No live Codex configuration is installed or modified.

### Evidence and compatibility

The verified legacy proof of concept is limited to Ubuntu Linux, Codex CLI 0.151.0, an external Expect script, and option 1 producing one-time acceptance for the harmless command `curl -I https://example.com`. It is historical UI evidence only. OpenAI does not document numeric approval-option ordering as a stable interface, so option 1 is not a supported interface and the proof does not establish hook support for Codex 0.151.0 or any other version.

The reviewed second isolated live verification against the locally installed `codex-cli 0.151.0` produced one real `PermissionRequest`, one structured allow response, completed the exact harmless `curl -I https://example.com` request with HTTP/2 200, showed no interactive approval prompt, and ended with a clean temporary repository and cleaned temporary state. This evidence supports only the exact registry entry in [docs/compatibility.md](docs/compatibility.md).

## Intended behavior

- `codex` continues to start ordinary Codex with normal approval behavior.
- `codex-autoapprover run -- ...` resolves and starts the user's existing official `codex` executable with inherited terminal I/O and a per-child arming token.
- Codex remains responsible for its normal TUI, authentication, configuration, sessions, model selection, sandbox, plugins, arguments, and exit behavior.
- For a version in the explicit verified allowlist, the launcher registers this executable as a synchronous `PermissionRequest` hook through a child-only Codex configuration override.
- The hook returns only the documented structured `allow` decision for the current request. It never returns a permanent or session-wide approval decision.
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

`verify-local-hook` is a separate, experimental, interactive-only verification mechanism. It is limited to the local target Codex 0.151.0, uses a temporary Git repository and child-only `-c` overrides, and requires the exact phrase `VERIFY CODEX 0.151.0 HOOK`. It does not promote compatibility or write persistent configuration. It must not be run again for this milestone.

## Implemented and unimplemented

Implemented in this milestone:

- CLI parsing for the five commands;
- official `codex` path resolution with recursive self-resolution protection;
- inherited stdin, stdout, and stderr child launch;
- Codex argument forwarding and exit-status propagation;
- random per-child arming token generation and cwd binding;
- bounded JSON parsing and exact documented allow-response serialization;
- fail-closed handling for unarmed, malformed, unknown, and mismatched requests;
- non-sensitive diagnostics and synthetic protocol/launcher tests;
- a typed compatibility registry with one reviewed Linux/local-CLI/Codex-0.151.0 entry;
- exact version, platform, surface, protocol, and `Bash` tool gating before child arming;

Not implemented or not verified:

- automatic installation, updating, or removal of live Codex hook configuration;
- IDE-extension integration, including its separate persistent-hook and secure-arming design;
- a permanent configuration/rules mode;
- packages or a supported release; and
- a direct App Server backend.

The arming token is inherited by descendants of the Codex child. That is a known limitation requiring stronger process binding before a public release.

Planned operating modes are `off/manual`, `observe`, `accept-once`, and a future `scoped/rules-based` mode. The current production path is a verified, child-local `accept-once` hook for one exact target; repeated requests in an armed session remain individually consequential.

## Development

Prerequisites are Rust edition 2024 and the dependencies declared in [Cargo.toml](Cargo.toml). The runtime uses `clap`, `getrandom`, `serde`, `serde_json`, `sha2`, `signal-hook`, `tempfile`, `thiserror`, and `which`; test support uses `assert_cmd` and `predicates`.

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

1. Add stronger Linux process/session binding and reduce descendant-token exposure.
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
