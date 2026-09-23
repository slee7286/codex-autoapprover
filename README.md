# codex-autoapprover

An unofficial, independent launcher for an existing official Codex CLI. It uses the structured `PermissionRequest` hook to return a one-request approval for a bound child session. It is not affiliated with or maintained by OpenAI.

**Pre-alpha: not yet qualified for public production use.** Automatic approvals can authorize consequential commands; this tool does not inspect their intent or strengthen the sandbox.

## Compatibility

The embedded [compatibility manifest](compatibility/manifest.json) is the sole production authority. It currently certifies **no targets**, including Linux 0.151.0. Admission requires equality across Codex version, native OS/build/distro, architecture, explicitly selected sandbox, foreground CLI surface, hook protocol, tool, native executable and bundled helper/resource SHA-256, and launch artifact/package identity. Unknown versions run ordinary Codex without the launcher's hook or broker credentials. A help/features probe does not establish compatibility. The legacy `--compatibility automatic` option and environment value now behave as `strict`; they cannot enable an unverified version.

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

## Linux artifact installer rehearsal

`scripts/install-linux.sh` accepts a prebuilt Linux executable, the matching manifest, and an expected lowercase SHA-256 from a separately authenticated release record. It stages and checks the executable before atomically selecting it under an owner-controlled install directory (`~/.local/bin` by default) with private release storage. `install`, `rollback`, `status`, and `uninstall` preserve `CODEX_HOME`; the installer refuses unmanaged files, unsafe directory chains, changed installed bytes, and unexpected release contents. A prior release is retained for rollback, and interrupted rollback/uninstall operations are recovered on the next invocation. The lock file remains after uninstall to serialize future installations.

There is **no authenticated public consumer artifact yet**. Local lifecycle tests use a development executable and a synthetic changed copy; they do not qualify a production release or exercise native Codex approval. Existing Cargo-installed executables are intentionally not adopted automatically.

`scripts/package_linux.py` creates a deterministic, explicitly unqualified development archive with the executable, installer, manifest, licence, README and a per-file digest record. `scripts/test-package-linux.sh` compares two independently built archives and installs the exact extracted bytes into a disposable directory. The adjacent checksum is unsigned and must not be treated as release authentication.

`scripts/locked_sbom.py` creates a preliminary SPDX 2.3 inventory from every package in `Cargo.lock`. It verifies each registry source archive against the locked SHA-256 before reading its declared license. The inventory covers optional, target, build and development dependencies; it is not a binary-specific SBOM or a completed license/vulnerability review. See [dependency review](docs/dependencies.md).

## Commands

```text
codex-autoapprover run [-- <codex arguments...>]
codex-autoapprover run --compatibility strict -- <codex arguments...>
codex-autoapprover diagnose
codex-autoapprover support-matrix
codex-autoapprover print-hook-config
codex-autoapprover verify-local-hook
```

The implemented foreground admission adapter requires an explicit `--sandbox-implementation` selection (for example `linux-bwrap`). The manifest is empty, so this option cannot currently arm a session. Recognized npm launchers are resolved to a native bundle before admission; Unix packages with group/world-writable files or directories cannot qualify. Windows bundle admission is explicitly disabled until directory ACL/reparse validation is implemented and tested natively. Profiles, arbitrary config/feature overrides and other subcommands currently use ordinary Codex; their qualification work remains open.

No subcommand means `run`. Arguments after `--` are forwarded to Codex. `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` is the default policy. `hook` is a protocol endpoint, not a public approval API. `support-matrix` prints the embedded manifest. `print-hook-config` refuses to print a support configuration without full admission; historical evidence cannot authorize it.

`verify-local-hook` is a legacy isolated, interactive, non-promoting experiment. It still needs adaptation to the current stable CLI and durable evidence collection; do not use its output as production certification. Its broker restricts candidates to exactly `curl -I https://example.com` on Linux or `curl.exe -I https://example.com` on Windows, with the expected tool and temporary working directory. Verification also requires exactly one broker connection, including connections whose frames cannot be parsed. A successful network request with zero observed permission events is inconclusive. It is not run automatically in CI.

The broker validates kernel peer credentials, process identity and ancestry, a per-session secret and request shape. See [security](SECURITY.md) for the same-user threat boundary and pending review.

## Updates and release preparation

[Watch Codex releases](.github/workflows/upstream-watch.yml) polls GitHub's official latest-full-release API every six hours, prepares unverified candidate metadata and a draft PR, and runs disposable-runner CLI probes and synthetic tests. It records exact GitHub asset digests and npm package integrities; candidate jobs check an exact npm lock, a script-free install and registry signatures before probing the installed shim. A bounded check back to the previous tag detects a skipped stable release and stops for manual recovery. An unchanged release needs no candidate branch after its PR is merged; automatic repair is eligible only when a draft PR is newly opened, with an explicit dispatch available to retry an existing branch. It neither certifies support nor modifies a user's installed Codex. Workflows need activation on the default branch and suitable repository permissions. Scheduled execution is best effort.

A bounded repair workflow is prepared locally but has not run on the default branch or produced native approval evidence. A [manual candidate provenance workflow](docs/release-provenance.md) is also prepared; it retains exact native build bytes, can attest their build origin under a protected environment, and separately gates both downloaded binaries on reviewed native evidence. Candidate provenance alone does not certify compatibility. Neither workflow has run. A Linux artifact lifecycle rehearsal is implemented; Windows consumer update/rollback, native certification and a protected final release remain required. The [production plan](docs/production-plan.md) records implementation, research, acceptance criteria and remaining work. Use the [ready-to-paste /goal](docs/production-goal.md) to continue through release preparation.

## Development

```sh
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/release_gate.py
./scripts/test-install-linux.sh target/debug/codex-autoapprover
./scripts/test-package-linux.sh target/debug/codex-autoapprover
python scripts/locked_sbom.py --output /tmp/codex-autoapprover-locked-dependencies.spdx.json
```

Native Windows CI also runs installer tests in Windows PowerShell 5.1 and PowerShell 7. Cross-compilation is not native execution evidence. The release-readiness workflow requires fresh reviewed evidence and intentionally fails until production qualification is complete.

## Documentation and licence

[Product contract](docs/product-contract.md) · [Architecture](docs/architecture.md) · [Hook protocol](docs/hook-protocol.md) · [Threat model](docs/threat-model.md) · [MIT licence](LICENSE)
