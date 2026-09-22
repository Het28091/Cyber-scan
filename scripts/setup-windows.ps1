[CmdletBinding()]
param([string]$Distribution = 'Ubuntu-24.04', [switch]$Offline)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Write-Error 'WSL is unavailable. Install WSL2 from Microsoft, restart Windows, then rerun setup.cmd.'
    exit 2
}
$Installed = (& wsl.exe --list --quiet 2>$null | Out-String) -replace "`0", ''
if ($LASTEXITCODE -ne 0 -or -not (@($Installed -split "`r?`n" | ForEach-Object { $_.Trim() }) -contains $Distribution)) {
    if ($Offline) { Write-Error "Offline setup requires the installed WSL2 distribution $Distribution."; exit 2 }
    Write-Host "Installing WSL and $Distribution. Windows may request administrator access or a restart."
    & wsl.exe --install --distribution $Distribution --no-launch
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'If administrator access is required, run setup.cmd from an Administrator terminal.'
        exit 2
    }
    Write-Host "Complete any requested restart. Open $Distribution once to create your Linux user, then rerun setup.cmd."
    exit 2
}
$Kernel = (& wsl.exe --distribution $Distribution --exec uname -r | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $Kernel -notmatch 'WSL2|microsoft-standard') {
    Write-Error "A working WSL2 distribution is required. Check wsl --list --verbose. If this is WSL1, migrate it deliberately with: wsl --set-version $Distribution 2"
    exit 2
}
$Arguments = @('--distribution', $Distribution, '--cd', $Root, '--exec', 'bash', 'scripts/setup-linux.sh')
if ($Offline) { $Arguments += '--offline' }
& wsl.exe @Arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
@{ distribution = $Distribution } | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $Root '.windows-runtime.json')
Write-Host 'Ready. Run: .\run.cmd scan --config config/offline.json'
Write-Host 'Dashboard: .\run.cmd dashboard'
