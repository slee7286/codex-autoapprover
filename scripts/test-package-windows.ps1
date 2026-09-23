$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
$binary = Join-Path $repository 'target\release\codex-autoapprover.exe'
$scratch = Join-Path $env:LOCALAPPDATA ('artifact-package-test-' + [guid]::NewGuid().ToString('N'))
try {
    if (-not (Test-Path -LiteralPath $binary)) { throw 'Build the release executable first.' }
    $first = Join-Path $scratch 'first'
    $second = Join-Path $scratch 'second'
    & python (Join-Path $PSScriptRoot 'package_windows.py') --binary $binary --output-dir $first | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'First Windows package build failed.' }
    & python (Join-Path $PSScriptRoot 'package_windows.py') --binary $binary --output-dir $second | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Second Windows package build failed.' }
    $archive = @(Get-ChildItem -LiteralPath $first -Filter '*.zip')
    if ($archive.Count -ne 1) { throw 'Expected exactly one Windows development archive.' }
    $other = Join-Path $second $archive[0].Name
    $digest = (Get-FileHash -LiteralPath $archive[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FileHash -LiteralPath $other -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digest) {
        throw 'Windows development archives are not reproducible.'
    }
    $checksum = [IO.File]::ReadAllText($archive[0].FullName + '.sha256')
    if ($checksum -cne "$digest  $($archive[0].Name)`n") { throw 'Development archive checksum differs.' }
    $extract = Join-Path $scratch 'extracted'
    Expand-Archive -LiteralPath $archive[0].FullName -DestinationPath $extract
    $packageRoot = Join-Path $extract ([IO.Path]::GetFileNameWithoutExtension($archive[0].Name))
    $record = Get-Content -LiteralPath (Join-Path $packageRoot 'artifact.json') -Raw | ConvertFrom-Json
    if ($record.release_status -cne 'unqualified-development-rehearsal' -or $record.platform -cne 'windows-x86_64') {
        throw 'Archive misstates development qualification.'
    }
    foreach ($file in $record.file_sha256.PSObject.Properties) {
        $path = Join-Path $packageRoot ($file.Name.Replace('/', '\'))
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $file.Value) { throw "Archive member digest mismatch: $($file.Name)" }
    }
    $members = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File)
    if ($members.Count -ne $record.file_sha256.PSObject.Properties.Count + 1) {
        throw 'Unexpected archive member count.'
    }
    $packagedBinary = Join-Path $packageRoot 'bin\codex-autoapprover.exe'
    $packagedManifest = Join-Path $packageRoot 'compatibility\manifest.json'
    $packagedInstaller = Join-Path $packageRoot 'scripts\install-windows-artifact.ps1'
    $installRoot = Join-Path $scratch 'installed'
    & $packagedInstaller install -Binary $packagedBinary -Sha256 $record.binary_sha256 -Manifest $packagedManifest -InstallDir $installRoot | Out-Null
    $live = Join-Path $installRoot 'codex-autoapprover.exe'
    if ((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash.ToLowerInvariant() -cne $record.binary_sha256) {
        throw 'Installed executable differs from the extracted archive bytes.'
    }
    & $packagedInstaller uninstall -InstallDir $installRoot | Out-Null
    if (Test-Path -LiteralPath $live) { throw 'Exact-byte rehearsal uninstall failed.' }
    Write-Host 'Windows development archive and exact-byte install rehearsal passed.'
} finally {
    if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force }
}
