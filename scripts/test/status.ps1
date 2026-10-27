#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Show the Kovyr Protection Alarm's state on this computer. Read-only.

.DESCRIPTION
    Prints, without changing anything:
      * the KovyrAgent service's state;
      * this computer's enrollment text (to paste on the admin page), which
        it also tries to copy to the clipboard;
      * Microsoft Defender's real-time protection and Tamper Protection;
      * this computer's clock, in local time and UTC;
      * the last lines of the agent's log.

    The agent's folder (C:\ProgramData\Kovyr) is open only to administrators,
    so run this in PowerShell opened with "Run as administrator":

        powershell -ExecutionPolicy Bypass -File .\status.ps1
#>
[CmdletBinding()]
param(
    # How many log lines to show.
    [ValidateRange(1, 500)]
    [int]$LogLines = 25
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

$programFiles = $env:ProgramW6432
if (-not $programFiles) { $programFiles = $env:ProgramFiles }
$exe = Join-Path $programFiles 'Kovyr\kovyr-agent.exe'
$state = Join-Path $env:ProgramData 'Kovyr'

Write-Host "== Kovyr Protection Alarm service"
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    Write-Host "Not installed: $exe is missing. Install kovyr-protection-alarm-x64.msi first."
    exit 1
}
& $exe service status
Write-Host ""

Write-Host "== This computer's enrollment (paste all of it on the admin page)"
$enroll = (& $exe enroll --print-pubkey 2>$null) -join "`r`n"
if ($enroll) {
    Write-Host $enroll
    try {
        Set-Clipboard -Value $enroll
        Write-Host "(Also copied to the clipboard.)"
    }
    catch { }
}
else {
    Write-Host "No device key yet: the installer makes it. Reinstall, or see Troubleshooting."
}
Write-Host ""

Write-Host "== Microsoft Defender"
try {
    $mp = Get-MpComputerStatus
    Write-Host ("Real-time protection: {0}" -f $(if ($mp.RealTimeProtectionEnabled) { 'on' } else { 'OFF' }))
    Write-Host ("Tamper Protection:    {0}" -f $(if ($mp.IsTamperProtected) { 'on' } else { 'OFF' }))
    Write-Host ("Antivirus:            {0}" -f $(if ($mp.AntivirusEnabled) { 'on' } else { 'OFF' }))
}
catch {
    Write-Host "Could not read Defender's status (another antivirus may be active)."
}
Write-Host ""

Write-Host "== Clock (the agent's reports are refused if this is more than 5 minutes off)"
$now = Get-Date
Write-Host ("Local: {0}   UTC: {1}" -f $now.ToString('yyyy-MM-dd HH:mm:ss'), $now.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))
Write-Host ""

Write-Host "== Last $LogLines lines of the agent log (times in UTC)"
$log = Join-Path $state 'logs\agent.log'
if (Test-Path -LiteralPath $log -PathType Leaf) {
    Get-Content -LiteralPath $log -Tail $LogLines
}
else {
    Write-Host "No log yet at $log."
}
