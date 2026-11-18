# SSC VPN uninstaller for Windows.
param(
    [string]$Prefix = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Bundled = Join-Path $Root "ssc.exe"

$cmd = Get-Command ssc -ErrorAction SilentlyContinue
if ($cmd) {
    $Bin = $cmd.Source
} elseif (Test-Path $Bundled) {
    $Bin = $Bundled
} else {
    Write-Error "ssc not found"
}

$argsList = @("uninstall")
if ($Prefix) {
    $argsList += @("--prefix", $Prefix)
}

& $Bin @argsList
exit $LASTEXITCODE
