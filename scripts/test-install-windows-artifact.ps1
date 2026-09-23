$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install-windows-artifact.ps1'
$repository = Split-Path $PSScriptRoot -Parent
$debugBinary = Join-Path $repository 'target\debug\codex-autoapprover.exe'
$releaseBinary = Join-Path $repository 'target\release\codex-autoapprover.exe'
$manifest = Join-Path $repository 'compatibility\manifest.json'
$scratchRoot = Join-Path $env:LOCALAPPDATA ('artifact space & unicode-' + [char]0x6d4b + [char]0x8bd5 + '-' + [guid]::NewGuid().ToString('N'))
$root = Join-Path $scratchRoot 'installed'
$unmanaged = Join-Path $env:LOCALAPPDATA ('artifact-unmanaged-' + [guid]::NewGuid().ToString('N'))
$unsafeAcl = Join-Path $env:LOCALAPPDATA ('artifact-acl-' + [guid]::NewGuid().ToString('N'))
$redirect = Join-Path $env:LOCALAPPDATA ('artifact-junction-' + [guid]::NewGuid().ToString('N'))
$real = Join-Path $env:LOCALAPPDATA ('artifact-real-' + [guid]::NewGuid().ToString('N'))
function Reject([scriptblock]$Command) {
    $rejected = $false
    try { & $Command | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe or invalid artifact operation was accepted.' }
}
function Assert-Live([string]$Digest) {
    $live = Join-Path $root 'codex-autoapprover.exe'
    $actual = (Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $Digest) { throw 'Live executable digest differs from expected release.' }
}
try {
    if (-not (Test-Path -LiteralPath $debugBinary) -or -not (Test-Path -LiteralPath $releaseBinary)) {
        throw 'Build both debug and release binaries before running artifact lifecycle tests.'
    }
    $debugDigest = (Get-FileHash -LiteralPath $debugBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $releaseDigest = (Get-FileHash -LiteralPath $releaseBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($debugDigest -ceq $releaseDigest) { throw 'Distinct binaries are required for upgrade testing.' }
    $configHome = Join-Path $scratchRoot 'external-config'
    [IO.Directory]::CreateDirectory($configHome) | Out-Null
    $config = Join-Path $configHome 'config.toml'
    [IO.File]::WriteAllText($config, "[windows]`nsandbox = 'elevated'`n")
    $beforeConfig = [IO.File]::ReadAllBytes($config)
    $oldCodexHome = $env:CODEX_HOME
    $env:CODEX_HOME = $configHome

    if ((& $installer status -InstallDir $root) -notmatch 'Current: none') { throw 'Fresh status is not empty.' }
    & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $root | Out-Null
    Assert-Live $debugDigest
    & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $root | Out-Null
    Assert-Live $debugDigest

    Reject { & $installer install -Binary $releaseBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $root }
    Assert-Live $debugDigest
    $wrongManifest = Join-Path $configHome 'wrong-manifest.json'
    [IO.File]::WriteAllText($wrongManifest, '{}')
    Reject { & $installer install -Binary $releaseBinary -Sha256 $releaseDigest -Manifest $wrongManifest -InstallDir $root }
    Assert-Live $debugDigest

    & $installer install -Binary $releaseBinary -Sha256 $releaseDigest -Manifest $manifest -InstallDir $root | Out-Null
    Assert-Live $releaseDigest
    $status = & $installer status -InstallDir $root
    if ($status -notmatch "Current: $releaseDigest" -or $status -notmatch "Previous: $debugDigest") {
        throw 'Upgrade did not retain the previous release.'
    }
    $live = Join-Path $root 'codex-autoapprover.exe'
    $held = [IO.File]::Open($live, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { Reject { & $installer rollback -InstallDir $root } } finally { $held.Dispose() }
    Assert-Live $releaseDigest
    & $installer rollback -InstallDir $root | Out-Null
    Assert-Live $debugDigest
    & $installer rollback -InstallDir $root | Out-Null
    Assert-Live $releaseDigest

    # Simulate process termination after File.Replace and before state commit.
    $stage = Join-Path $root ('.stage-' + [guid]::NewGuid().ToString('N') + '.exe')
    [IO.File]::Copy((Join-Path (Join-Path $root 'releases') "$debugDigest.exe"), $stage)
    [IO.File]::WriteAllText((Join-Path $root '.journal'), "schema=1`naction=rollback`nold=$releaseDigest`nnew=$debugDigest`n", [Text.Encoding]::ASCII)
    [IO.File]::Replace($stage, $live, (Join-Path $root '.replace-backup.exe'), $false)
    $status = & $installer status -InstallDir $root
    if ($status -notmatch "Current: $debugDigest" -or $status -notmatch "Previous: $releaseDigest") {
        throw 'Interrupted replacement was not recovered.'
    }
    Assert-Live $debugDigest
    $afterConfig = [IO.File]::ReadAllBytes($config)
    if ([Convert]::ToBase64String($beforeConfig) -cne [Convert]::ToBase64String($afterConfig)) {
        throw 'Artifact installation changed CODEX_HOME configuration.'
    }
    & $installer uninstall -InstallDir $root | Out-Null
    if (Test-Path -LiteralPath (Join-Path $root 'codex-autoapprover.exe')) { throw 'Uninstall retained the executable.' }
    if (Test-Path -LiteralPath (Join-Path $root '.codex-autoapprover-owned')) { throw 'Uninstall retained ownership state.' }
    & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $root | Out-Null
    [IO.File]::WriteAllText((Join-Path $root '.journal'), "schema=1`naction=uninstall`nold=$debugDigest`nnew=none`n", [Text.Encoding]::ASCII)
    if ((& $installer status -InstallDir $root) -notmatch 'Current: none') {
        throw 'Interrupted uninstall was not recovered.'
    }
    if (Test-Path -LiteralPath (Join-Path $root 'codex-autoapprover.exe')) { throw 'Recovered uninstall retained the executable.' }
    & $installer uninstall -InstallDir $root | Out-Null

    [IO.Directory]::CreateDirectory($unmanaged) | Out-Null
    [IO.File]::WriteAllText((Join-Path $unmanaged 'codex-autoapprover.exe'), 'unmanaged')
    Reject { & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $unmanaged }
    if ([IO.File]::ReadAllText((Join-Path $unmanaged 'codex-autoapprover.exe')) -cne 'unmanaged') {
        throw 'Unmanaged executable was changed.'
    }
    [IO.Directory]::CreateDirectory($unsafeAcl) | Out-Null
    $acl = Get-Acl -LiteralPath $unsafeAcl
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $users,
        [Security.AccessControl.FileSystemRights]::Modify,
        ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $unsafeAcl -AclObject $acl
    Reject { & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $unsafeAcl }
    [IO.Directory]::CreateDirectory($real) | Out-Null
    New-Item -ItemType Junction -Path $redirect -Target $real -ErrorAction Stop | Out-Null
    Reject { & $installer install -Binary $debugBinary -Sha256 $debugDigest -Manifest $manifest -InstallDir $redirect }
    Write-Host 'Windows artifact lifecycle tests passed.'
} finally {
    $env:CODEX_HOME = $oldCodexHome
    foreach ($path in @($scratchRoot, $unmanaged, $unsafeAcl, $redirect, $real)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
}
