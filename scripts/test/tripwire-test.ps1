<#
.SYNOPSIS
    Kovyr Protection Alarm test: make the ransomware tripwire fire, safely.

.DESCRIPTION
    Creates a NEW folder in your Documents folder (or your Desktop, if
    Documents is missing), named "Kovyr tripwire test <date time>". It puts
    200 small dummy text files in it, renames them all to a new extension
    within a few seconds (the pattern ransomware leaves when it encrypts
    files), waits a little, then deletes exactly those files and the folder.

    It touches nothing else:
      * it stops if its folder already exists;
      * it renames and deletes only the files it created, by their exact names;
      * it removes the folder only if the folder is empty by then.

    Why 200: the agent trips when, within 60 seconds, it sees at least 100
    renames and writes, at least 50 of them renames to a new extension, and
    those at least 60% of all renames (docs/tripwire.md). 200 renames to a
    new extension clear all three on their own.

    Run it as yourself (no administrator rights needed), on a test computer
    that has the Kovyr Protection Alarm installed and enrolled:

        powershell -ExecutionPolicy Bypass -File .\tripwire-test.ps1

    Then expect the "Possible ransomware" email within about 2 minutes.
    Wait at least 30 minutes before running it again (the agent sends at
    most one immediate alarm per 10 minutes, and Kovyr emails once per
    episode).
#>
[CmdletBinding()]
param(
    # How many dummy files to make and rename.
    [ValidateRange(120, 1000)]
    [int]$Files = 200,
    # How long to leave the renamed files before cleaning up.
    [ValidateRange(0, 300)]
    [int]$WaitSeconds = 15
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# The agent watches each profile's own Desktop and Documents folders
# (C:\Users\<you>\Documents), not folders that OneDrive or Group Policy
# moved somewhere else, and not shortcuts or links.
$parent = $null
foreach ($name in @('Documents', 'Desktop')) {
    $candidate = Join-Path $env:USERPROFILE $name
    $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
    if ($item -and $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        $parent = $candidate
        break
    }
}
if (-not $parent) {
    Write-Host "Neither $env:USERPROFILE\Documents nor $env:USERPROFILE\Desktop is a normal folder on this computer"
    Write-Host "(OneDrive or a company policy may have moved them). The agent does not watch moved folders yet,"
    Write-Host "so this test cannot trip it here. Nothing was changed. See 'Troubleshooting' in testing-on-your-pc.md."
    exit 2
}

$stamp = Get-Date -Format 'yyyy-MM-dd HHmmss'
$folder = Join-Path $parent "Kovyr tripwire test $stamp"
if (Test-Path -LiteralPath $folder) {
    Write-Host "$folder already exists. This script only works in a folder it creates itself, so it stops here."
    exit 2
}
New-Item -ItemType Directory -Path $folder | Out-Null
Write-Host "Made the test folder $folder"

# Every file this script makes, by exact name, and where it is now.
$current = New-Object 'System.Collections.Generic.List[string]'
try {
    for ($i = 1; $i -le $Files; $i++) {
        $path = Join-Path $folder ('kovyr-dummy-{0:D4}.txt' -f $i)
        [IO.File]::WriteAllText($path, "Kovyr Protection Alarm tripwire test file. Safe to delete.`r`n")
        $current.Add($path)
    }
    Write-Host "Made $Files dummy files. Waiting 3 seconds..."
    Start-Sleep -Seconds 3

    Write-Host "Renaming them all from .txt to .kovyr-test, as fast as possible..."
    $watch = [Diagnostics.Stopwatch]::StartNew()
    for ($i = 0; $i -lt $current.Count; $i++) {
        $to = $current[$i] + '.kovyr-test'
        [IO.File]::Move($current[$i], $to)
        $current[$i] = $to
    }
    $watch.Stop()
    Write-Host ("Renamed {0} files in {1:N1} seconds." -f $current.Count, $watch.Elapsed.TotalSeconds)
    Write-Host ""
    Write-Host "If the Kovyr Protection Alarm is installed and enrolled, it has just sent an extra check-in"
    Write-Host "reporting possible ransomware. The 'Possible ransomware' email should arrive within about"
    Write-Host "2 minutes (halden's switches AGENT_VERIFY_ENABLED and AGENT_ALERTS_ENABLED must be 1)."
    Write-Host ""
    if ($WaitSeconds -gt 0) {
        Write-Host "Cleaning up in $WaitSeconds seconds..."
        Start-Sleep -Seconds $WaitSeconds
    }
}
finally {
    # Delete only this script's files, then the folder if it is empty.
    $left = 0
    foreach ($path in $current) {
        try {
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
        }
        catch { $left++ }
    }
    $others = @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue)
    if ($others.Count -eq 0 -and $left -eq 0) {
        Remove-Item -LiteralPath $folder -Force
        Write-Host "Cleaned up: the test folder and its files are gone."
    }
    else {
        Write-Host "Left $folder in place: it holds $($others.Count) item(s) this script did not delete. Delete it by hand."
    }
}
