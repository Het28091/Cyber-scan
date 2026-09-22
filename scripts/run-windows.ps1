param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ScannerArgs)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$StatePath = Join-Path $Root '.windows-runtime.json'
if (-not (Test-Path $StatePath)) { Write-Error 'Run setup.cmd first.'; exit 2 }
$State = Get-Content -Raw $StatePath | ConvertFrom-Json
$Arguments = @('--distribution', $State.distribution, '--cd', $Root, '--exec', 'python3', 'scripts/launch.py') + $ScannerArgs
& wsl.exe @Arguments
exit $LASTEXITCODE
