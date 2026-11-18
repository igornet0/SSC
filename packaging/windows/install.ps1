# SSC VPN installer for Windows.
# Run:  powershell -ExecutionPolicy Bypass -File .\install.ps1
param(
    [string]$Prefix = "",
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bin = Join-Path $Root "ssc.exe"

if (-not (Test-Path $Bin)) {
    Write-Error "ssc.exe not found next to install.ps1"
}

$argsList = @("install")
if ($Prefix) {
    $argsList += @("--prefix", $Prefix)
}
if ($SkipSetup) {
    $argsList += "--skip-setup"
}

& $Bin @argsList
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Open a new terminal, then run:  ssc status"
