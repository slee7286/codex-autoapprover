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

Configuration is parsed as TOML, unrelated values and comments are retained, and the original file is backed up before replacement. Invalid or unknown sandbox settings, hardlinked or reparse-point configuration files, and symlinked or junction configuration directories fail without a rewrite. Configuration input is limited to 4 MiB. Repeated application is idempotent. Close configuration editors during installation. Native ACL, interruption and installer testing is still required before release. Direct `cargo install` performs no configuration step.

## Linux artifact installer rehearsal

`scripts/install-linux.sh` accepts a prebuilt Linux executable, the matching manifest, and an expected lowercase SHA-256 from a separately authenticated release record. It stages and checks the executable before atomically selecting it under an owner-controlled install directory (`~/.local/bin` by default) with private release storage. An identical reinstall rechecks the installed executable's manifest and execution health before returning success. `install`, `rollback`, `status`, and `uninstall` preserve `CODEX_HOME`; the installer refuses unmanaged files, unsafe directory chains, changed installed bytes, and unexpected release contents. A prior release is retained for rollback, and install, rollback and uninstall journals finish interrupted pointer changes on the next invocation. Recovery rejects malformed journals and unmanaged pointer files. The lock file remains after uninstall to serialize future installations.

There is **no authenticated public consumer artifact yet**. Local lifecycle tests use a development executable and a synthetic changed copy; they do not qualify a production release or exercise native Codex approval. Existing Cargo-installed executables are intentionally not adopted automatically.

`scripts/package_linux.py` creates a deterministic, explicitly unqualified development archive with the executable, installer, manifest, licence, README and a per-file digest record. `scripts/test-package-linux.sh` compares two independently built archives, then installs, upgrades, rolls back and uninstalls exact extracted bytes from two byte-distinct development archives in a disposable directory. The adjacent checksum is unsigned and must not be treated as release authentication.

## Windows artifact installer rehearsal

The separate `scripts/install-windows-artifact.ps1` accepts an extracted Windows x86_64 executable, its manifest and a lowercase SHA-256 obtained from an independently authenticated record:

```powershell
.\scripts\install-windows-artifact.ps1 install -Binary .\bin\codex-autoapprover.exe -Manifest .\compatibility\manifest.json -Sha256 '<authenticated-sha256>'
.\scripts\install-windows-artifact.ps1 status
.\scripts\install-windows-artifact.ps1 rollback
.\scripts\install-windows-artifact.ps1 uninstall
```

It manages a private install directory under `LOCALAPPDATA` (default `%LOCALAPPDATA%\codex-autoapprover\bin`), leaving `CODEX_HOME`, `PATH` and the Windows sandbox setting alone. Invoke the managed executable by its full path until a consumer launcher is qualified. The intended replacement is a same-volume `File.Replace`; a lock and journal reconcile a process interruption, and a locked live executable causes the update to fail. Uninstall leaves the lock file to serialize later installs. An existing Cargo installation is not adopted or overwritten. The installer refuses redirected or broadly writable install directories, unmanaged entries and changed release bytes. Native Windows ACL, locked-file, long-path, interruption and disk-full behavior still needs actual PowerShell 5.1/7 execution and review.

`scripts/package_windows.py` prepares a deterministic, **unqualified** development ZIP on native Windows; `scripts/test-package-windows.ps1` is prepared to compare reproducible ZIPs and rehearse install, reinstall, upgrade, rollback and uninstall using the exact bytes extracted from two distinct ZIPs. Its adjacent checksum and internal `artifact.json` are unsigned and do not authenticate a download. There is no authenticated public consumer artifact yet.

`scripts/locked_sbom.py` creates a preliminary SPDX 2.3 inventory from every package in `Cargo.lock`. It verifies each registry source archive against the locked SHA-256 before reading its declared license. The inventory covers optional, target, build and development dependencies; it is not a binary-specific SBOM or a completed license/vulnerability review. See [dependency review](docs/dependencies.md).

`scripts/binary_sbom.py` creates a native Linux or Windows x86_64 SPDX document for one exact executable SHA-256 and its Cargo normal/build dependency graph. It verifies the embedded support manifest, uses checksum-verified crate sources, excludes dev-only and other-platform crates, and refuses an existing output that differs from the executable or source. It records build inputs, including proc macros; exact linked code, the Rust toolchain, OS components and independent dependency review still need separate assessment. The prepared candidate workflow stages and rechecks this document for each native binary, then requests a binary-subject SBOM attestation under the protected candidate environment. No workflow run has validated the Windows path or produced a signed consumer artifact.

`scripts/build_record.py` prepares a bounded, exact-digest native build observation alongside each candidate executable and SPDX file. It records the Rust/Cargo versions, Git revision, clean-tree status and selected OS facts, and the separate qualification runner rechecks its source, binary and toolchain binding. The release gate requires a retained build record for each reviewed native tuple. It is review material, not proof of reproducibility or complete linked-component inventory. The workflow path has not run.

`scripts/check_reproducible_build.py` compares a candidate native executable with two separate offline, locked release builds of its clean source commit. The candidate workflow retains a source/toolchain/binary-bound `reproducibility.json`, and the release gate requires a reviewed reference to it. Linux same-host repeatability passed locally; the prepared Windows workflow has not run. This observation does not replace signed provenance or an independent cross-host build.

`scripts/locked_licenses.py` creates an offline, deterministic bundle of available license and notice texts from those verified archives. Two locked crates lack matching top-level texts; independent license review and a final consumer notice selection remain necessary.

## Commands

```text
codex-autoapprover run [-- <codex arguments...>]
codex-autoapprover run --compatibility strict -- <codex arguments...>
codex-autoapprover diagnose
codex-autoapprover support-matrix
codex-autoapprover print-hook-config
codex-autoapprover verify-local-hook [--diagnostic-dir <existing-directory>]
```

The implemented foreground admission adapter requires an explicit `--sandbox-implementation` selection (for example `linux-bwrap`). The manifest is empty, so this option cannot currently arm a session. Recognized npm launchers are resolved to a native bundle before admission; Unix packages with group/world-writable files or directories cannot qualify. A conservative Windows directory owner/DACL and reparse-point check is now prepared and cross-compiled, but has not run on native Windows or received independent review; no Windows tuple is certified. Profiles, arbitrary config/feature overrides and other subcommands currently use ordinary Codex; their qualification work remains open.

No subcommand means `run`. Arguments after `--` are forwarded to Codex. `CODEX_AUTOAPPROVER_COMPATIBILITY=strict` is the default policy. `hook` is a protocol endpoint, not a public approval API. `support-matrix` prints the embedded manifest. `print-hook-config` refuses to print a support configuration without full admission; historical evidence cannot authorize it.

`verify-local-hook` is a legacy interactive, non-promoting experiment with a temporary repository. It still needs adaptation to the current stable CLI and isolated hook composition; do not use its output as production certification. Its broker restricts candidates to one nonce-bound `curl` (`curl.exe` on Windows) HEAD request to a verifier-owned loopback listener, with the expected tool and temporary working directory. Verification requires exactly one broker connection, including connections whose frames cannot be parsed, one allow and one independently received local request. A request with zero observed permission events is inconclusive. Codex must review and trust the temporary hook normally. This experiment is not run automatically in CI. With `--diagnostic-dir`, it creates a unique subdirectory under the specified existing directory containing a hash-only broker audit and `diagnostic.json` (directory mode 0700 on Unix; inherited ACL on Windows). The report is explicitly unqualified, omits the command and credentials, and cannot satisfy the release gate; earlier failures before a completed child observation may leave no report.

The broker validates kernel peer credentials, process identity and ancestry, a per-session secret and request shape. See [security](SECURITY.md) for the same-user threat boundary and pending review.

## Updates and release preparation

[Watch Codex releases](.github/workflows/upstream-watch.yml) polls GitHub every six hours, scans a bounded release history back to the checked-in baseline, and queues newer stable versions oldest first. It prepares one previously unhandled, unverified candidate PR per poll; a closed PR remains a maintainer decision. Schema-3 candidate metadata pins the release, native asset and npm identities plus the Git tag object and its source commit. The watcher rechecks the baseline and open PRs against current official identities; candidate runners refresh their exact version by tag before checking native asset digests, an exact npm lock, a script-free installation and registry signatures. A moved or deleted source tag, missing history or changed artifact stops for manual recovery. The repair worker also checks that its upstream checkout matches the pinned tag object and commit before using it as untrusted context. Automatic repair is eligible only when a draft PR is newly opened; a manual dispatch can retry an exact existing version. This does not certify support or change a user's installed Codex. The workflow still needs activation and exercise on the default branch with suitable repository permissions. Scheduled execution is best effort.

A bounded repair workflow is prepared locally but has not run on the default branch or produced native approval evidence. A [manual candidate provenance workflow](docs/release-provenance.md) is also prepared; it retains exact native build bytes, can attest their build origin under a protected environment, and separately gates both downloaded binaries on reviewed native evidence. Candidate provenance alone does not certify compatibility. Neither workflow has run. Linux artifact lifecycle testing has passed locally; a Windows artifact lifecycle and development archive are prepared for native testing. Native certification, authenticated consumer distribution and a protected final release remain required. The [production plan](docs/production-plan.md) records implementation, research, acceptance criteria and remaining work. Use the [ready-to-paste /goal](docs/production-goal.md) to continue through release preparation.

## Development

```sh
cargo fmt --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --target x86_64-pc-windows-msvc --all-targets
cargo build --release --locked --bin codex-autoapprover
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/release_gate.py
./scripts/test-install-linux.sh target/debug/codex-autoapprover
./scripts/test-package-linux.sh target/debug/codex-autoapprover
python scripts/locked_sbom.py --output /tmp/codex-autoapprover-locked-dependencies.spdx.json
python scripts/binary_sbom.py --offline --binary target/release/codex-autoapprover --output /tmp/codex-autoapprover-linux-x86_64.spdx.json
```

The prepared native Windows candidate workflow runs source and artifact installer tests in Windows PowerShell 5.1 and PowerShell 7, plus an exact-byte development ZIP lifecycle rehearsal. It has not run. Cross-compilation and Linux PowerShell syntax checks are not native execution evidence. The release-readiness workflow requires fresh reviewed evidence and intentionally fails until production qualification is complete.

## Documentation and licence

[Product contract](docs/product-contract.md) · [Architecture](docs/architecture.md) · [Hook protocol](docs/hook-protocol.md) · [Threat model](docs/threat-model.md) · [MIT licence](LICENSE)
