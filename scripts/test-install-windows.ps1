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
    $linkedHome = Join-Path $root 'hardlink-home'
    [System.IO.Directory]::CreateDirectory($linkedHome) | Out-Null
    $linkedConfig = Join-Path $linkedHome 'config.toml'
    $linkedAlias = Join-Path $linkedHome 'alias.toml'
    $linkedOriginal = "[windows]`nsandbox = 'elevated'`n"
    [System.IO.File]::WriteAllText($linkedConfig, $linkedOriginal, $utf8)
    New-Item -ItemType HardLink -Path $linkedAlias -Target $linkedConfig -ErrorAction Stop | Out-Null
    $rejected = $false
    try { & $installer -CodexHome $linkedHome -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated } catch { $rejected = $true }
    if (-not $rejected) { throw 'Hardlinked configuration accepted' }
    if ([System.IO.File]::ReadAllText($linkedConfig) -cne $linkedOriginal) { throw 'Hardlinked configuration changed' }
    if ([System.IO.File]::ReadAllText($linkedAlias) -cne $linkedOriginal) { throw 'Hardlink alias changed' }

    $realHome = Join-Path $root 'real-junction-home'
    $junctionHome = Join-Path $root 'junction-home'
    [System.IO.Directory]::CreateDirectory($realHome) | Out-Null
    New-Item -ItemType Junction -Path $junctionHome -Target $realHome -ErrorAction Stop | Out-Null
    $rejected = $false
    try { & $installer -CodexHome $junctionHome -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated } catch { $rejected = $true }
    if (-not $rejected) { throw 'Junction configuration home accepted' }
    if (Test-Path -LiteralPath (Join-Path $realHome 'config.toml')) { throw 'Junction target configuration changed' }
    if (Test-Path -LiteralPath (Join-Path $realHome '.autoapprover-config.lock')) { throw 'Junction target lock created' }

    & $installer -CodexHome (Join-Path $root 'new-home') -ConfigureOnly -BinaryPath $binary -WindowsSandbox unelevated
    Write-Host 'Windows installation configuration tests passed.'
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
