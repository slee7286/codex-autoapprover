param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('install', 'rollback', 'uninstall', 'status')]
    [string]$Action,
    [string]$Binary,
    [string]$Sha256,
    [string]$Manifest,
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'codex-autoapprover\bin')
)

# An authenticated SHA-256 is an input, not a checksum supplied by this archive.
# The live executable is replaced on its own volume; a journal reconciles a
# process interruption between replacement and the state-file update.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Native Windows is required.' }
if (-not $env:LOCALAPPDATA) { throw 'LOCALAPPDATA is required.' }
if ($Action -eq 'install') {
    if (-not $Binary -or -not $Manifest -or $Sha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'install requires -Binary, -Manifest and an independently authenticated lowercase -Sha256.'
    }
} elseif ($Binary -or $Manifest -or $Sha256) {
    throw 'Artifact arguments are only valid with install.'
}

function Entry([string]$Path) {
    return Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
}
function Assert-Regular([string]$Path) {
    $item = Entry $Path
    if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::Directory) -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe or missing regular file: $Path"
    }
}
function Digest([string]$Path) {
    Assert-Regular $Path
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Copy-Private([string]$Source, [string]$Destination) {
    Assert-Regular $Source
    $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $inputStream.CopyTo($outputStream)
            $outputStream.Flush($true)
        } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    Assert-ManagedFile $Destination
}
function Assert-Acl([string]$Path, [bool]$CallerOwned) {
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -cne $script:callerSid -and
        ($CallerOwned -or ($owner -cne 'S-1-5-18' -and $owner -cne 'S-1-5-32-544'))) {
        throw "Path owned by another principal: $Path"
    }
    $write = [int]([Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership)
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            (([int]$rule.FileSystemRights -band $write) -ne 0) -and
            $sid -cne $script:callerSid -and $sid -cne 'S-1-5-18' -and
            $sid -cne 'S-1-5-32-544' -and $sid -cne 'S-1-3-0') {
            throw "Path grants write access to another principal: $Path"
        }
    }
}
function Assert-Directory([string]$Path) {
    $item = Entry $Path
    if (-not $item -or -not ($item.Attributes -band [IO.FileAttributes]::Directory) -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Unsafe directory: $Path"
    }
    Assert-Acl $Path $false
}
function Assert-ManagedFile([string]$Path) {
    Assert-Regular $Path
    Assert-Acl $Path $true
}
function Validate-Location([bool]$Create) {
    if ($InstallDir -cnotmatch '\A[A-Za-z]:\\') {
        throw 'InstallDir must be an absolute local path.'
    }
    $script:anchor = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
    $script:root = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    if (-not $script:root.StartsWith($script:anchor + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'InstallDir must be inside LOCALAPPDATA.'
    }
    $drive = [IO.Path]::GetPathRoot($script:anchor)
    $cursor = $drive
    foreach ($part in $script:anchor.Substring($drive.Length).Split('\')) {
        if (-not $part) { throw 'Invalid LOCALAPPDATA path.' }
        $cursor = Join-Path $cursor $part
        $item = Entry $cursor
        if (-not $item -or -not ($item.Attributes -band [IO.FileAttributes]::Directory) -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "Redirected LOCALAPPDATA directory chain: $cursor"
        }
    }
    Assert-Directory $script:anchor
    $relative = $script:root.Substring($script:anchor.Length + 1)
    $cursor = $script:anchor
    foreach ($part in $relative.Split('\')) {
        if (-not $part -or $part -eq '.' -or $part -eq '..') { throw 'Noncanonical InstallDir.' }
        $cursor = Join-Path $cursor $part
        if (-not (Entry $cursor)) {
            if (-not $Create) { return $false }
            [IO.Directory]::CreateDirectory($cursor) | Out-Null
        }
        Assert-Directory $cursor
    }
    $owner = (Get-Acl -LiteralPath $script:root).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -cne $script:callerSid) { throw 'InstallDir must be owned by the caller.' }
    return $true
}
function Read-Record([string]$Path, [string]$Pattern) {
    Assert-Regular $Path
    if ((Entry $Path).Length -gt 300) { throw "Oversized state record: $Path" }
    $body = [IO.File]::ReadAllText($Path, [Text.Encoding]::ASCII)
    $match = [regex]::Match($body, $Pattern, [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { throw "Invalid state record: $Path" }
    return $match
}
function Write-Record([string]$Path, [string]$Body, [bool]$Replace) {
    $temporary = Join-Path $script:root ('.record-' + [guid]::NewGuid().ToString('N') + '.tmp')
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::ASCII.GetBytes($Body)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ($Replace) {
        [IO.File]::Replace($temporary, $Path, $script:stateBackup, $false)
        if (Entry $script:stateBackup) { [IO.File]::Delete($script:stateBackup) }
    } else {
        [IO.File]::Move($temporary, $Path)
    }
}
function State {
    if (-not (Entry $script:statePath)) { return @{ current = 'none'; previous = 'none' } }
    $record = Read-Record $script:statePath '\Aschema=1\ncurrent=(none|[0-9a-f]{64})\nprevious=(none|[0-9a-f]{64})\n\z'
    if ($record.Groups[1].Value -eq 'none' -and $record.Groups[2].Value -ne 'none') {
        throw 'Invalid empty current state.'
    }
    return @{ current = $record.Groups[1].Value; previous = $record.Groups[2].Value }
}
function Save-State([string]$Current, [string]$Previous) {
    $body = "schema=1`ncurrent=$Current`nprevious=$Previous`n"
    Write-Record $script:statePath $body ([bool](Entry $script:statePath))
}
function Journal {
    if (-not (Entry $script:journalPath)) { return $null }
    $record = Read-Record $script:journalPath '\Aschema=1\naction=(install|rollback|uninstall)\nold=(none|[0-9a-f]{64})\nnew=(none|[0-9a-f]{64})\n\z'
    return @{ action = $record.Groups[1].Value; old = $record.Groups[2].Value; new = $record.Groups[3].Value }
}
function Write-Journal([string]$Operation, [string]$Old, [string]$New) {
    if (Entry $script:journalPath) { throw 'Unrecovered install journal.' }
    Write-Record $script:journalPath "schema=1`naction=$Operation`nold=$Old`nnew=$New`n" $false
}
function Assert-Inventory {
    $names = @('.codex-autoapprover-owned', '.lock', '.journal', '.state', '.state-backup',
        '.replace-backup.exe', 'codex-autoapprover.exe', 'releases')
    foreach ($item in Get-ChildItem -LiteralPath $script:root -Force) {
        if ($names -cnotcontains $item.Name -and
            $item.Name -cnotmatch '\A\.(record-[0-9a-f]{32}\.tmp|stage-[0-9a-f]{32}\.exe)\z') {
            throw "Unexpected install entry: $($item.FullName)"
        }
        if ($item.Name -ne 'releases') { Assert-ManagedFile $item.FullName }
    }
    if (Entry $script:releaseDir) {
        Assert-Directory $script:releaseDir
        foreach ($item in Get-ChildItem -LiteralPath $script:releaseDir -Force) {
            if ($item.Name -cnotmatch '\A[0-9a-f]{64}\.exe\z') { throw "Unexpected release entry: $($item.FullName)" }
            Assert-ManagedFile $item.FullName
            $expected = $item.Name.Substring(0, 64)
            if ((Digest $item.FullName) -cne $expected) { throw "Damaged release: $($item.FullName)" }
        }
    }
}
function Clean-Temporary {
    foreach ($item in Get-ChildItem -LiteralPath $script:root -Force) {
        if ($item.Name -cmatch '\A\.(record-[0-9a-f]{32}\.tmp|stage-[0-9a-f]{32}\.exe)\z') {
            Assert-Regular $item.FullName
            [IO.File]::Delete($item.FullName)
        }
    }
    foreach ($path in @($script:replaceBackup, $script:stateBackup)) {
        if (Entry $path) { Assert-Regular $path; [IO.File]::Delete($path) }
    }
}
function Finish-Uninstall {
    if (Entry $script:live) { Assert-Regular $script:live; [IO.File]::Delete($script:live) }
    if (Entry $script:releaseDir) {
        Assert-Directory $script:releaseDir
        foreach ($item in Get-ChildItem -LiteralPath $script:releaseDir -Force) {
            if ($item.Name -cnotmatch '\A[0-9a-f]{64}\.exe\z') { throw 'Unexpected release during uninstall.' }
            Assert-Regular $item.FullName
            [IO.File]::Delete($item.FullName)
        }
        [IO.Directory]::Delete($script:releaseDir)
    }
    Clean-Temporary
    foreach ($path in @($script:statePath, $script:journalPath, $script:marker)) {
        if (Entry $path) { Assert-Regular $path; [IO.File]::Delete($path) }
    }
}
function Recover {
    $pending = Journal
    if ($pending) {
        if ($pending.action -eq 'uninstall') {
            if ($pending.new -ne 'none') { throw 'Invalid uninstall journal.' }
            Finish-Uninstall
            return
        }
        if ($pending.new -eq 'none' -or $pending.old -eq $pending.new) { throw 'Invalid replacement journal.' }
        $saved = State
        $actual = if (Entry $script:live) { Assert-ManagedFile $script:live; Digest $script:live } else { 'none' }
        if ($actual -ceq $pending.new) {
            if ($saved.current -cne $pending.old -and $saved.current -cne $pending.new) {
                throw 'State differs from completed replacement journal.'
            }
            Save-State $pending.new $pending.old
        } elseif ($actual -cne $pending.old -or $saved.current -cne $pending.old) {
            throw 'Live executable differs from interrupted replacement journal.'
        }
        Clean-Temporary
        [IO.File]::Delete($script:journalPath)
    } else {
        Clean-Temporary
    }
}
function Assert-Snapshot {
    $saved = State
    $actual = if (Entry $script:live) { Assert-ManagedFile $script:live; Digest $script:live } else { 'none' }
    if ($actual -cne $saved.current) { throw 'Live executable differs from managed state.' }
    foreach ($digest in @($saved.current, $saved.previous)) {
        if ($digest -ne 'none' -and (Digest (Join-Path $script:releaseDir "$digest.exe")) -cne $digest) {
            throw 'Managed release differs from state.'
        }
    }
    return $saved
}
function Probe([string]$Path, [string]$Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Path
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "Executable health probe timed out: $Path"
        }
        if ($process.ExitCode -ne 0) { throw "Executable health probe failed: $Path" }
    } finally { $process.Dispose() }
}

$script:callerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (-not (Validate-Location ($Action -eq 'install'))) {
    if ($Action -eq 'rollback') { throw 'No managed installation to roll back.' }
    if ($Action -eq 'status') { Write-Output "Current: none`nPrevious: none" }
    if ($Action -eq 'uninstall') { Write-Output 'Already uninstalled.' }
    return
}
$script:live = Join-Path $script:root 'codex-autoapprover.exe'
$script:releaseDir = Join-Path $script:root 'releases'
$script:statePath = Join-Path $script:root '.state'
$script:stateBackup = Join-Path $script:root '.state-backup'
$script:replaceBackup = Join-Path $script:root '.replace-backup.exe'
$script:journalPath = Join-Path $script:root '.journal'
$script:marker = Join-Path $script:root '.codex-autoapprover-owned'
$lockPath = Join-Path $script:root '.lock'
if (Entry $lockPath) { Assert-ManagedFile $lockPath }
$lock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
    Assert-Inventory
    if (-not (Entry $script:marker)) {
        $unmanaged = @(Get-ChildItem -LiteralPath $script:root -Force | Where-Object { $_.Name -cne '.lock' })
        if ($unmanaged.Count) { throw 'Existing unmanaged installation; refusing to replace it.' }
        if ($Action -ne 'install') {
            if ($Action -eq 'rollback') { throw 'No managed installation to roll back.' }
            if ($Action -eq 'status') { Write-Output "Current: none`nPrevious: none" }
            if ($Action -eq 'uninstall') { Write-Output 'Already uninstalled.' }
            return
        }
        [IO.File]::WriteAllText($script:marker, "codex-autoapprover-windows-installer-v1`n", [Text.Encoding]::ASCII)
    }
    Assert-Regular $script:marker
    if ((Entry $script:marker).Length -gt 128) { throw 'Oversized install marker.' }
    $markerText = [IO.File]::ReadAllText($script:marker, [Text.Encoding]::ASCII)
    if ($markerText -cne "codex-autoapprover-windows-installer-v1`n") { throw 'Unknown install marker.' }
    Recover
    if (-not (Entry $script:marker)) {
        if ($Action -eq 'install') {
            [IO.File]::WriteAllText($script:marker, "codex-autoapprover-windows-installer-v1`n", [Text.Encoding]::ASCII)
        } else {
            if ($Action -eq 'rollback') { throw 'Interrupted uninstall completed; nothing to roll back.' }
            if ($Action -eq 'status') { Write-Output "Current: none`nPrevious: none" }
            if ($Action -eq 'uninstall') { Write-Output 'Recovered interrupted uninstall.' }
            return
        }
    }
    $saved = Assert-Snapshot
    switch ($Action) {
        'status' { Write-Output "Current: $($saved.current)`nPrevious: $($saved.previous)"; break }
        'uninstall' {
            Write-Journal 'uninstall' $saved.current 'none'
            Finish-Uninstall
            Write-Output 'Uninstalled.'
            break
        }
        'rollback' {
            if ($saved.previous -eq 'none') { throw 'No previous release to roll back.' }
            $target = $saved.previous
            $operation = 'rollback'
            break
        }
        'install' {
            Assert-Regular $Binary
            Assert-Regular $Manifest
            if ((Digest $Binary) -cne $Sha256) { throw 'Artifact differs from authenticated SHA-256.' }
            $target = $Sha256
            $operation = 'install'
            break
        }
    }
    if ($Action -eq 'status' -or $Action -eq 'uninstall') { return }
    if (-not (Entry $script:releaseDir)) { [IO.Directory]::CreateDirectory($script:releaseDir) | Out-Null }
    Assert-Directory $script:releaseDir
    $release = Join-Path $script:releaseDir "$target.exe"
    if ($Action -eq 'install') {
        if (-not (Entry $release)) {
            $temp = Join-Path $script:root ('.stage-' + [guid]::NewGuid().ToString('N') + '.exe')
            Copy-Private $Binary $temp
            if ((Digest $temp) -cne $target) { throw 'Staged artifact digest mismatch.' }
            Probe $temp ('verify-manifest --manifest "' + [IO.Path]::GetFullPath($Manifest) + '"')
            Probe $temp '--help'
            if ((Digest $temp) -cne $target) { throw 'Staged artifact changed after health probe.' }
            [IO.File]::Move($temp, $release)
        } else {
            if ((Digest $release) -cne $target) { throw 'Existing release digest mismatch.' }
            Probe $release ('verify-manifest --manifest "' + [IO.Path]::GetFullPath($Manifest) + '"')
            Probe $release '--help'
        }
    }
    if ($saved.current -ceq $target) {
        Write-Output "Already installed: $target"
        return
    }
    if ((Digest $release) -cne $target) { throw 'Target release digest mismatch.' }
    if ($Action -eq 'rollback') { Probe $release '--help' }
    $stage = Join-Path $script:root ('.stage-' + [guid]::NewGuid().ToString('N') + '.exe')
    Copy-Private $release $stage
    if ((Digest $stage) -cne $target) { throw 'Replacement stage digest mismatch.' }
    Write-Journal $operation $saved.current $target
    if ($saved.current -eq 'none') {
        [IO.File]::Move($stage, $script:live)
    } else {
        [IO.File]::Replace($stage, $script:live, $script:replaceBackup, $false)
    }
    Recover
    $committed = Assert-Snapshot
    if ($committed.current -cne $target) { throw 'Replacement did not commit.' }
    Write-Output "Installed: $target"
} finally {
    $lock.Dispose()
}
