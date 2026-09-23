# codex-autoapprover

An unofficial, independent launcher for an existing official Codex CLI. It uses the structured `PermissionRequest` hook to return a one-request approval for a bound child session. It is not affiliated with or maintained by OpenAI.

**Pre-alpha: not yet qualified for public production use.** Automatic approvals can authorize consequential commands; this tool does not inspect their intent or strengthen the sandbox.

## Compatibility

General automatic approval is restricted to exact reviewed Codex version/OS entries. Unknown versions run ordinary Codex without the launcher's hook or broker credentials. A help/features probe does not establish compatibility. The legacy `--compatibility automatic` option and environment value now behave as `strict`; they cannot enable an unverified version.

The repository retains a historical Linux/local-CLI/Codex 0.151.0 entry. It is not qualification of the current release artifact. **Windows 0.156.0 is unverified**, even when the unelevated sandbox successfully runs a shell command. Public release qualification is deliberately blocked in [release-policy.json](compatibility/release-policy.json). See [compatibility](docs/compatibility.md) and the [production plan](docs/production-plan.md).

## Windows source installation

From the codex-autoapprover checkout, execute the saved file; do not paste its contents into an interactive prompt:

```powershell
.\scripts\install-windows.ps1
```

Rust and an existing official Codex installation are prerequisites. The script reinstalls the launcher using Cargo and preserves Codex configuration by default. Existing `codexa` aliases that point to the installed launcher continue to work.

To opt into the previously diagnosed Windows sandbox fallback while installing or reinstalling:

```powershell
.\scripts\install-windows.ps1 -WindowsSandbox unelevated
```

This explicitly sets `windows.sandbox = "unelevated"` in `$env:CODEX_HOME/config.toml`, or `$env:USERPROFILE/.codex/config.toml` by default. It affects ordinary Codex too and uses weaker isolation. Later default reinstalls preserve that choice. Use `-WindowsSandbox elevated` to reverse the setting, or `-ConfigureOnly -WindowsSandbox unelevated` with the updated binary already installed to skip rebuilding. No installer setting makes an unverified approval hook eligible.

Configuration is parsed as TOML, unrelated values and comments are retained, and the original file is backed up before replacement. Invalid or unknown sandbox settings fail without a rewrite. Repeated application is idempotent. Close configuration editors during installation. Native ACL, interruption and installer testing is still required before release. Direct `cargo install` performs no configuration step.

## Commands

```text
codex-autoapprover run [-- <codex arguments...>]
codex-autoapprover run --compatibility strict -- <codex arguments...>
codex-autoapprover diagnose
codex-autoapprover support-matrix
codex-autoapprover print-hook-config
codex-autoapprover verify-local-hook
```

No subcommand means `run`. Arguments after `--` are forwarded to Codex. `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` is the default policy. `hook` is a protocol endpoint, not a public approval API. `print-hook-config` prints only for a historical reviewed tuple; it never installs a hook.

`verify-local-hook` is an isolated, interactive, non-promoting experiment. Its broker restricts candidates to exactly `curl -I https://example.com` on Linux or `curl.exe -I https://example.com` on Windows, with the expected tool and temporary working directory. A successful network request with zero observed permission events is inconclusive. It is not run automatically in CI.

The broker validates kernel peer credentials, process identity and ancestry, a per-session secret and request shape. See [security](SECURITY.md) for the same-user threat boundary and pending review.

## Updates and release preparation

[Watch Codex releases](.github/workflows/upstream-watch.yml) polls the official release API every six hours, prepares unverified candidate metadata and a draft PR, and runs disposable-runner CLI probes and synthetic tests. It neither certifies support nor modifies a user's installed Codex. Workflows need activation on the default branch and suitable repository permissions. Scheduled execution is best effort.

A protected repair worker, complete native certification, artifact signing and consumer update/rollback remain required. The [production plan](docs/production-plan.md) records implementation, research, acceptance criteria and remaining work. Use the [ready-to-paste /goal](docs/production-goal.md) to continue through release preparation.

## Development

```sh
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/release_gate.py
```

Native Windows CI also runs installer tests in Windows PowerShell 5.1 and PowerShell 7. Cross-compilation is not native execution evidence. The release-readiness workflow requires fresh reviewed evidence and intentionally fails until production qualification is complete.

## Documentation and licence

[Product contract](docs/product-contract.md) · [Architecture](docs/architecture.md) · [Hook protocol](docs/hook-protocol.md) · [Threat model](docs/threat-model.md) · [MIT licence](LICENSE)
