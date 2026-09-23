$ErrorActionPreference = 'Stop'
$root = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$installer = Join-Path $PSScriptRoot 'install-windows.ps1'
$binary = Join-Path (Split-Path $PSScriptRoot -Parent) 'target\debug\codex-autoapprover.exe'
$utf8 = [System.Text.UTF8Encoding]::new($false)
try {
    if (-not (Test-Path $binary)) { throw 'Run cargo build --locked --bin codex-autoapprover first.' }
    $cases = @(
        '',
        "model = 'example'`r`n[windows]`r`nsandbox = 'elevated' # keep comment`r`n[other]`r`nvalue = 1`r`n",
        "[windows]`nsandbox_private_desktop = false`n[other]`nvalue = 1",
        'windows.sandbox = "elevated"',
        'windows = { sandbox = "elevated", sandbox_private_desktop = false }'
    )
    for ($i = 0; $i -lt $cases.Count; $i++) {
        $configDirectory = Join-Path $root "space & unicode-测试-$i"
        [System.IO.Directory]::CreateDirectory($configDirectory) | Out-Null
        $configPath = Join-Path $configDirectory 'config.toml'
        [System.IO.File]::WriteAllText($configPath, $cases[$i], $utf8)
        & $installer -CodexHome $configDirectory -ConfigureOnly -BinaryPath $binary
        if ([System.IO.File]::ReadAllText($configPath) -cne $cases[$i]) { throw 'Default installation changed configuration' }
        & $installer -CodexHome $configDirectory -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated
        $first = [System.IO.File]::ReadAllText($configPath)
        if ($first -notmatch 'sandbox\s*=\s*"unelevated"') { throw 'Sandbox setting missing' }
        if ($i -eq 1 -and -not $first.Contains('# keep comment')) { throw 'Comment lost' }
        $backups = @(Get-ChildItem $configDirectory -Filter '*.bak')
        if ($backups.Count -ne 1) { throw 'Expected one backup' }
        if ([System.IO.File]::ReadAllText($backups[0].FullName) -cne $cases[$i]) { throw 'Backup differs' }
        & $installer -CodexHome $configDirectory -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated
        if ([System.IO.File]::ReadAllText($configPath) -cne $first) { throw 'Not idempotent' }
        if (@(Get-ChildItem $configDirectory -Filter '*.bak').Count -ne 1) { throw 'Redundant backup' }
    }
    foreach ($unsupported in @('[windows', "[windows]`nsandbox = 12", "[windows]`nsandbox = 'future'")) {
        [System.IO.File]::WriteAllText($configPath, $unsupported, $utf8)
        $rejected = $false
        try { & $installer -CodexHome $configDirectory -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated } catch { $rejected = $true }
        if (-not $rejected) { throw 'Invalid configuration accepted' }
        if ([System.IO.File]::ReadAllText($configPath) -cne $unsupported) { throw 'Rejected configuration changed' }
    }
    & $installer -CodexHome (Join-Path $root 'new-home') -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated
    Write-Host 'Windows installation configuration tests passed.'
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
