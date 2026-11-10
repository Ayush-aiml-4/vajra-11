<#
.SYNOPSIS
    Upgrades `VajraGuardService` binaries in place while preserving DPAPI device identity (`identity.json` + `device-key.bin`).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublishDirectory,

    [string]$InstallDirectory = "$env:ProgramFiles\VAJRA\WindowsAgent",
    [string]$DataDirectory = "$env:ProgramData\VAJRA\WindowsAgent"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'VajraGuardService'
$SourceExe = Join-Path $PublishDirectory 'Vajra.WindowsAgent.exe'
if (-not (Test-Path -LiteralPath $SourceExe)) {
    throw "Published binary not found at $SourceExe."
}

$Svc = Get-Service -Name $ServiceName -ErrorAction Stop
if ($Svc.Status -ne 'Stopped') {
    Write-Host "[VAJRA] Stopping $ServiceName gracefully..."
    Stop-Service -Name $ServiceName -Force
    $Svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}

Copy-Item -Path (Join-Path $PublishDirectory '*') -Destination $InstallDirectory -Recurse -Force

if (Test-Path -LiteralPath (Join-Path $DataDirectory 'device-key.bin')) {
    Write-Host "[VAJRA] Preserved existing DPAPI device key in $DataDirectory."
}

Start-Service -Name $ServiceName
$Updated = Get-Service -Name $ServiceName
Write-Host "[VAJRA] Upgrade complete. Service status: $($Updated.Status)"
