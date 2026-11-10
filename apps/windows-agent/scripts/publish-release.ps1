<#
.SYNOPSIS
    Builds and publishes the VAJRA Windows Agent release artifact (`win-x64` or `win-arm64`).
.DESCRIPTION
    Produces a clean release publish directory under `artifacts/publish/<RuntimeIdentifier>`
    ready for explicit owner installation via `install-service.ps1`.
#>
[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$RuntimeIdentifier = 'win-x64',

    [switch]$SelfContained
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AgentRoot = Split-Path -Parent $PSScriptRoot
$PublishDir = Join-Path $AgentRoot "artifacts\publish\$RuntimeIdentifier"

Write-Host "[VAJRA] Restoring and publishing Vajra.WindowsAgent ($RuntimeIdentifier)..."
dotnet publish "$AgentRoot\Vajra.WindowsAgent.csproj" `
    -c Release `
    -r $RuntimeIdentifier `
    --self-contained:$($SelfContained.IsPresent) `
    -o $PublishDir

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE"
}

$ExePath = Join-Path $PublishDir 'Vajra.WindowsAgent.exe'
if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Expected executable not found at $ExePath"
}

$Hash = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "[VAJRA] Publish complete: $ExePath"
Write-Host "[VAJRA] SHA-256: $Hash"
