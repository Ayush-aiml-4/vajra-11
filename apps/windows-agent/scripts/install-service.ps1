<#
.SYNOPSIS
    Explicitly installs and configures `VajraGuardService` in Windows Service Control Manager (SCM).
.DESCRIPTION
    Requires an elevated PowerShell prompt. Prepares `%ProgramData%\VAJRA\WindowsAgent` with
    explicit Administrators / SYSTEM / Service ACLs, copies published binaries to Program Files,
    registers `VajraGuardService` (`Automatic Delayed Start`), and configures SCM crash recovery.
    Never hides the service or bypasses standard Windows SCM controls.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PublishDirectory,

    [string]$InstallDirectory = "$env:ProgramFiles\VAJRA\WindowsAgent",
    [string]$DataDirectory = "$env:ProgramData\VAJRA\WindowsAgent",
    [string]$ServerBaseUrl = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'VajraGuardService'
$DisplayName = 'VAJRA Personal Security Guard'
$Description = 'VAJRA owner-controlled endpoint protection, signed heartbeat, and bounded event telemetry service.'

$Principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required to register a Windows Service.'
}

$SourceExe = Join-Path $PublishDirectory 'Vajra.WindowsAgent.exe'
if (-not (Test-Path -LiteralPath $SourceExe)) {
    throw "Published binary not found at $SourceExe. Run scripts/publish-release.ps1 first."
}

New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $DataDirectory | Out-Null

# Restrict DPAPI key directory to SYSTEM and Administrators
icacls $DataDirectory /inheritance:r /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" | Out-Null

Copy-Item -Path (Join-Path $PublishDirectory '*') -Destination $InstallDirectory -Recurse -Force
$InstalledExe = Join-Path $InstallDirectory 'Vajra.WindowsAgent.exe'

if (-not [string]::IsNullOrWhiteSpace($ServerBaseUrl)) {
    [Environment]::SetEnvironmentVariable('VAJRA_SERVER_BASE_URL', $ServerBaseUrl.TrimEnd('/'), 'Machine')
    [Environment]::SetEnvironmentVariable('VAJRA_REQUIRE_HTTPS', 'true', 'Machine')
}

$Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $Existing) {
    sc.exe create $ServiceName binPath= "`"$InstalledExe`"" start= delayed-auto DisplayName= "`"$DisplayName`"" | Out-Null
} else {
    if ($Existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    sc.exe config $ServiceName binPath= "`"$InstalledExe`"" start= delayed-auto DisplayName= "`"$DisplayName`"" | Out-Null
}

sc.exe description $ServiceName "$Description" | Out-Null
# Restart after 60s on first two unexpected crashes; reset failure counter after 24 hours (86400s)
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/""/0 | Out-Null
sc.exe failureflag $ServiceName 1 | Out-Null

Write-Host "[VAJRA] Installed $ServiceName at $InstalledExe"
Write-Host "[VAJRA] Data directory: $DataDirectory"
Write-Host "[VAJRA] Next step: enroll (`"$InstalledExe`" enroll --bundle <JSON>) and confirm in the VAJRA web console, then run Start-Service $ServiceName."
