#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Make the Kovyr Protection Alarm check in now.

.DESCRIPTION
    Restarts the KovyrAgent service (or starts it, if it is stopped). The
    agent checks in as soon as it starts, so this saves waiting up to 15
    minutes for the next scheduled check-in. It changes nothing else.

    Run it in PowerShell opened with "Run as administrator":

        powershell -ExecutionPolicy Bypass -File .\check-in-now.ps1
#>
[CmdletBinding()]
param()
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$svc = Get-Service -Name 'KovyrAgent' -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Host "The Kovyr Protection Alarm is not installed on this computer."
    exit 1
}
Restart-Service -Name 'KovyrAgent'
$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Write-Host ("Restarted the Kovyr Protection Alarm at {0}. It checks in within a few seconds;" -f (Get-Date -Format 'HH:mm:ss'))
Write-Host "the admin page shows it after halden's next verify pass (about a minute)."
