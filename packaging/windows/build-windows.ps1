# Build LLM Vault for Windows: release binaries, tests, portable ZIP and the Inno Setup installer.
# Usage:  powershell -ExecutionPolicy Bypass -File packaging\windows\build-windows.ps1 [-Sign] [-SkipTests]
param(
    [switch]$Sign,
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\..\.."
Set-Location $root

$version = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
Write-Host "LLM Vault $version" -ForegroundColor Cyan

if (-not $SkipTests) {
    cargo test --release
    if ($LASTEXITCODE -ne 0) { throw "tests failed" }
}
cargo build --release --bins
if ($LASTEXITCODE -ne 0) { throw "build failed" }

New-Item -ItemType Directory -Force dist | Out-Null

if ($Sign) {
    # Requires signtool in PATH and a code signing certificate (Authenticode / Microsoft Artifact Signing).
    foreach ($exe in @("target\release\llmvault.exe", "target\release\llmvault-server.exe")) {
        signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /a $exe
        if ($LASTEXITCODE -ne 0) { throw "signing $exe failed" }
    }
}

# Portable ZIP (a file named 'portable' next to the exe keeps all data in .\data)
$portable = "dist\LLM-Vault-$version-windows-x64-portable"
Remove-Item -Recurse -Force $portable -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $portable | Out-Null
Copy-Item target\release\llmvault.exe, target\release\llmvault-server.exe, LICENSE, README.md $portable
Copy-Item -Recurse examples "$portable\examples"
Set-Content "$portable\portable" "Delete this file to store data in the user profile instead of .\data"
Compress-Archive -Force -Path "$portable\*" -DestinationPath "$portable.zip"
Remove-Item -Recurse -Force $portable

# Installer
$iscc = @("$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup)" }
$isccArgs = @("/DAppVersion=$version", "packaging\windows\llmvault.iss")
if ($Sign) { $isccArgs = @("/DSign=1") + $isccArgs }
& $iscc @isccArgs
if ($LASTEXITCODE -ne 0) { throw "installer build failed" }

Get-ChildItem dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$h  $($_.Name)"
} | Set-Content dist\SHA256SUMS.txt
Get-Content dist\SHA256SUMS.txt
