$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
$debugBinary = Join-Path $repository 'target\debug\codex-autoapprover.exe'
$releaseBinary = Join-Path $repository 'target\release\codex-autoapprover.exe'
$scratch = Join-Path $env:LOCALAPPDATA ('artifact-package-test-' + [guid]::NewGuid().ToString('N'))
$oldCodexHome = $env:CODEX_HOME

function Verify-ExtractedArchive {
    param([string]$Root)
    $record = Get-Content -LiteralPath (Join-Path $Root 'artifact.json') -Raw | ConvertFrom-Json
    if ($record.release_status -cne 'unqualified-development-rehearsal' -or $record.platform -cne 'windows-x86_64') {
        throw 'Archive misstates development qualification.'
    }
    foreach ($file in $record.file_sha256.PSObject.Properties) {
        $path = Join-Path $Root ($file.Name.Replace('/', '\'))
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $file.Value) { throw "Archive member digest mismatch: $($file.Name)" }
    }
    $members = @(Get-ChildItem -LiteralPath $Root -Recurse -File)
    if ($members.Count -ne $record.file_sha256.PSObject.Properties.Count + 1) {
        throw 'Unexpected archive member count.'
    }
    if ($record.binary_sha256 -cne $record.file_sha256.'bin/codex-autoapprover.exe') {
        throw 'Archive binary digest differs from its member record.'
    }
    return $record
}

function Assert-LiveDigest {
    param([string]$Path, [string]$Digest)
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Digest) {
        throw 'Installed executable differs from the extracted archive bytes.'
    }
}

try {
    if (-not (Test-Path -LiteralPath $debugBinary) -or -not (Test-Path -LiteralPath $releaseBinary)) {
        throw 'Build both debug and release executables first.'
    }
    $first = Join-Path $scratch 'first'
    $second = Join-Path $scratch 'second'
    $upgrade = Join-Path $scratch 'upgrade'
    foreach ($output in @(
        @{ Binary = $debugBinary; Directory = $first },
        @{ Binary = $debugBinary; Directory = $second },
        @{ Binary = $releaseBinary; Directory = $upgrade }
    )) {
        & python (Join-Path $PSScriptRoot 'package_windows.py') --binary $output.Binary --output-dir $output.Directory | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Windows development package build failed.' }
    }

    $archive = @(Get-ChildItem -LiteralPath $first -Filter '*.zip')
    $upgradeArchive = @(Get-ChildItem -LiteralPath $upgrade -Filter '*.zip')
    if ($archive.Count -ne 1 -or $upgradeArchive.Count -ne 1 -or $archive[0].Name -cne $upgradeArchive[0].Name) {
        throw 'Expected one development archive per binary with the same package name.'
    }
    $other = Join-Path $second $archive[0].Name
    $digest = (Get-FileHash -LiteralPath $archive[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $other -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
        throw 'Windows development archives are not reproducible.'
    }
    $upgradeDigest = (Get-FileHash -LiteralPath $upgradeArchive[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($upgradeDigest -ceq $digest) { throw 'Byte-distinct binaries produced identical archives.' }
    foreach ($item in @(
        @{ File = $archive[0].FullName; Digest = $digest },
        @{ File = $upgradeArchive[0].FullName; Digest = $upgradeDigest }
    )) {
        $checksum = [IO.File]::ReadAllText($item.File + '.sha256')
        $expected = $item.Digest + '  ' + [IO.Path]::GetFileName($item.File) + [char]10
        if ($checksum -cne $expected) { throw 'Development archive checksum differs.' }
    }

    $extract = Join-Path $scratch 'extracted'
    $upgradeExtract = Join-Path $scratch 'extracted-upgrade'
    Expand-Archive -LiteralPath $archive[0].FullName -DestinationPath $extract
    Expand-Archive -LiteralPath $upgradeArchive[0].FullName -DestinationPath $upgradeExtract
    $packageRoot = Join-Path $extract ([IO.Path]::GetFileNameWithoutExtension($archive[0].Name))
    $upgradeRoot = Join-Path $upgradeExtract ([IO.Path]::GetFileNameWithoutExtension($upgradeArchive[0].Name))
    $record = Verify-ExtractedArchive $packageRoot
    $upgradeRecord = Verify-ExtractedArchive $upgradeRoot
    if ($record.binary_sha256 -ceq $upgradeRecord.binary_sha256) {
        throw 'Exact-byte upgrade needs a distinct executable.'
    }

    $configHome = Join-Path $scratch 'codex home'
    [IO.Directory]::CreateDirectory($configHome) | Out-Null
    $preserved = Join-Path $configHome 'session.txt'
    [IO.File]::WriteAllText($preserved, 'preserve authentication and sessions')
    $preservedDigest = (Get-FileHash -LiteralPath $preserved -Algorithm SHA256).Hash.ToLowerInvariant()
    $env:CODEX_HOME = $configHome

    $packagedBinary = Join-Path $packageRoot 'bin\codex-autoapprover.exe'
    $packagedManifest = Join-Path $packageRoot 'compatibility\manifest.json'
    $packagedInstaller = Join-Path $packageRoot 'scripts\install-windows-artifact.ps1'
    $upgradeBinary = Join-Path $upgradeRoot 'bin\codex-autoapprover.exe'
    $upgradeManifest = Join-Path $upgradeRoot 'compatibility\manifest.json'
    $upgradeInstaller = Join-Path $upgradeRoot 'scripts\install-windows-artifact.ps1'
    $installRoot = Join-Path $scratch 'installed'
    $live = Join-Path $installRoot 'codex-autoapprover.exe'

    & $packagedInstaller install -Binary $packagedBinary -Sha256 $record.binary_sha256 -Manifest $packagedManifest -InstallDir $installRoot | Out-Null
    Assert-LiveDigest $live $record.binary_sha256
    & $packagedInstaller install -Binary $packagedBinary -Sha256 $record.binary_sha256 -Manifest $packagedManifest -InstallDir $installRoot | Out-Null
    if ((& $packagedInstaller status -InstallDir $installRoot) -notmatch 'Previous: none') {
        throw 'Identical reinstall created a previous release.'
    }
    & $upgradeInstaller install -Binary $upgradeBinary -Sha256 $upgradeRecord.binary_sha256 -Manifest $upgradeManifest -InstallDir $installRoot | Out-Null
    Assert-LiveDigest $live $upgradeRecord.binary_sha256
    $status = & $upgradeInstaller status -InstallDir $installRoot
    if ($status -notmatch "Current: $($upgradeRecord.binary_sha256)" -or $status -notmatch "Previous: $($record.binary_sha256)") {
        throw 'Exact-byte upgrade did not retain the previous archive executable.'
    }
    & $upgradeInstaller rollback -InstallDir $installRoot | Out-Null
    Assert-LiveDigest $live $record.binary_sha256
    $status = & $upgradeInstaller status -InstallDir $installRoot
    if ($status -notmatch "Current: $($record.binary_sha256)" -or $status -notmatch "Previous: $($upgradeRecord.binary_sha256)") {
        throw 'Exact-byte rollback did not restore the prior archive executable.'
    }
    & $upgradeInstaller uninstall -InstallDir $installRoot | Out-Null
    if (Test-Path -LiteralPath $live) { throw 'Exact-byte rehearsal uninstall failed.' }
    if ((Get-FileHash -LiteralPath $preserved -Algorithm SHA256).Hash.ToLowerInvariant() -cne $preservedDigest) {
        throw 'Archive lifecycle changed CODEX_HOME content.'
    }
    Write-Host 'Windows development archives and exact-byte install/upgrade/rollback/uninstall rehearsal passed.'
} finally {
    $env:CODEX_HOME = $oldCodexHome
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
