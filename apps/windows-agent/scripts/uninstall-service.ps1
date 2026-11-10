<#
.SYNOPSIS
    Stops and removes `VajraGuardService` cleanly via standard Windows SCM tools.
.DESCRIPTION
    By default preserves `%ProgramData%\VAJRA\WindowsAgent` unless `-PurgeState` is passed.
    Remind the owner to also revoke or decommission the device in the VAJRA web console.
#>
[CmdletBinding()]
param(
    [string]$InstallDirectory = "$env:ProgramFiles\VAJRA\WindowsAgent",
    [string]$DataDirectory = "$env:ProgramData\VAJRA\WindowsAgent",
    [switch]$PurgeState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'VajraGuardService'
$Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Svc) {
    if ($Svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $Svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    sc.exe delete $ServiceName | Out-Null
    Write-Host "[VAJRA] Removed Windows Service $ServiceName."
} else {
    Write-Host "[VAJRA] Service $ServiceName is not registered."
}

if (Test-Path -LiteralPath $InstallDirectory) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
    Write-Host "[VAJRA] Removed binaries at $InstallDirectory."
}

if ($PurgeState.IsPresent -and (Test-Path -LiteralPath $DataDirectory)) {
    Remove-Item -LiteralPath $DataDirectory -Recurse -Force
    Write-Host "[VAJRA] Purged local DPAPI device state at $DataDirectory."
}

Write-Host "[VAJRA] If this PC is still listed in your VAJRA web console, revoke or remove it under Devices."
