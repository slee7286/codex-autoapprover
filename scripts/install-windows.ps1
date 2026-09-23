param(
    [string]$CodexHome = $(if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $env:USERPROFILE '.codex' }),
    [ValidateSet('preserve', 'elevated', 'unelevated')]
    [string]$WindowsSandbox = 'preserve',
    [switch]$ConfigureOnly,
    [string]$BinaryPath
)

# One invocation ensures that a failed install cannot fall through to configuration.
& {
    $ErrorActionPreference = 'Stop'
    $WindowsSandbox = $WindowsSandbox.ToLowerInvariant()
    if ($env:OS -ne 'Windows_NT') { throw 'This installer requires native Windows.' }
    if (-not $ConfigureOnly) {
        if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
            throw 'Run the saved scripts/install-windows.ps1 file from the codex-autoapprover checkout; do not paste its contents into the prompt.'
        }
        if ($BinaryPath) { throw '-BinaryPath is only supported with -ConfigureOnly.' }
        $repo = Split-Path $PSScriptRoot -Parent
        $manifest = Join-Path $repo 'Cargo.toml'
        if (-not (Test-Path -LiteralPath $manifest)) { throw 'The codex-autoapprover checkout is missing Cargo.toml.' }
        & cargo install --path $repo --locked --force --bin codex-autoapprover
        if ($LASTEXITCODE -ne 0) { throw 'Installation failed; Codex configuration was not changed.' }
        $cargoRoot = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
        $BinaryPath = Join-Path $cargoRoot 'bin\codex-autoapprover.exe'
        & $BinaryPath verify-manifest --manifest (Join-Path $repo 'compatibility\manifest.json')
        if ($LASTEXITCODE -ne 0) { throw 'Installed binary and source compatibility manifests differ; configuration was not changed.' }
    }
    if ($WindowsSandbox -ne 'preserve') {
        if (-not $BinaryPath) { $BinaryPath = (Get-Command codex-autoapprover -CommandType Application -ErrorAction Stop).Source }
        & $BinaryPath configure-windows-sandbox --codex-home $CodexHome --mode $WindowsSandbox
        if ($LASTEXITCODE -ne 0) { throw 'Configuration failed. The installed binary may have been updated; inspect the error before retrying.' }
    } else {
        Write-Host 'Codex sandbox configuration preserved. Use -WindowsSandbox unelevated only to opt into the weaker Windows fallback.'
    }
    Write-Host 'Automatic approvals require the complete certified executable/host/sandbox/protocol tuple. No current target is production-qualified; Windows 0.156.0 remains unverified.'
}
