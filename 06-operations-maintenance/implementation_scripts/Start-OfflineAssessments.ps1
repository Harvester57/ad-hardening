# Start-OfflineAssessments.ps1
# Description: Triggers a PingCastle security audit scan and SharpHound data collection.

param (
    [string]$DiagnosticsPath = "C:\Diagnostics",
    [string]$DomainName = "target.domain.local"
)

Write-Host "--- Starting AD Hardening Offline Assessment Scans ---" -ForegroundColor Cyan

if (-not (Test-Path $DiagnosticsPath)) {
    New-Item -Path $DiagnosticsPath -ItemType Directory -Force | Out-Null
}

$PingCastlePath = Join-Path $DiagnosticsPath "PingCastle.exe"
$SharpHoundPath = Join-Path $DiagnosticsPath "SharpHound.exe"

# 1. Execute PingCastle
if (Test-Path $PingCastlePath) {
    Write-Host "[+] Executing PingCastle..." -ForegroundColor Yellow
    $params = @(
        "--server", $DomainName,
        "--level", "level_Default",
        "--xml",
        "--no_update",
        "--output", $DiagnosticsPath
    )
    Start-Process -FilePath $PingCastlePath -ArgumentList $params -Wait -NoNewWindow
    Write-Host "[+] PingCastle scan complete." -ForegroundColor Green
} else {
    Write-Error "PingCastle.exe not found at $PingCastlePath. Please place the binary to execute."
}

# 2. Execute SharpHound
if (Test-Path $SharpHoundPath) {
    Write-Host "[+] Executing SharpHound..." -ForegroundColor Yellow
    $zipName = "AD_BloodHound_Export_" + (Get-Date -Format "yyyyMMdd") + ".zip"
    $zipPath = Join-Path $DiagnosticsPath $zipName
    
    $params = @(
        "--CollectionMethods", "All",
        "--Domain", $DomainName,
        "--ZipFileName", $zipPath
    )
    Start-Process -FilePath $SharpHoundPath -ArgumentList $params -Wait -NoNewWindow
    Write-Host "[+] SharpHound collection complete. Saved to: $zipPath" -ForegroundColor Green
} else {
    Write-Error "SharpHound.exe not found at $SharpHoundPath. Please place the binary to execute."
}
