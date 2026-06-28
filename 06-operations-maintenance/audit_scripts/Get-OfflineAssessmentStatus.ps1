# Get-OfflineAssessmentStatus.ps1
# Description: Audits the presence of PingCastle and SharpHound tools and the age of recent reports.

Write-Host "--- Auditing Active Directory Security Assessment Tools ---" -ForegroundColor Cyan

$DiagnosticsPath = "C:\Diagnostics" # Common diagnostics path
$PingCastlePath = Join-Path $DiagnosticsPath "PingCastle.exe"
$SharpHoundPath = Join-Path $DiagnosticsPath "SharpHound.exe"
$ReportAgeDays = 30

$Compliant = $true

# 1. Check PingCastle
if (Test-Path $PingCastlePath) {
    Write-Host "[+] PingCastle executable found: $PingCastlePath" -ForegroundColor Green
    
    # Check if reports have been generated in the last 30 days
    $reports = Get-ChildItem -Path $DiagnosticsPath -Filter "*pingcastle*.xml" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$ReportAgeDays) }
    if ($reports) {
        Write-Host "    [+] Found $($reports.Count) recent PingCastle report(s) (within last $ReportAgeDays days)." -ForegroundColor Green
    } else {
        Write-Warning "    [-] No recent PingCastle report found (older than $ReportAgeDays days)."
        $Compliant = $false
    }
} else {
    Write-Warning "[-] PingCastle executable NOT found at: $PingCastlePath"
    $Compliant = $false
}

# 2. Check SharpHound
if (Test-Path $SharpHoundPath) {
    Write-Host "[+] SharpHound executable found: $SharpHoundPath" -ForegroundColor Green
    
    # Check if data exports exist
    $exports = Get-ChildItem -Path $DiagnosticsPath -Filter "*BloodHound*.zip" -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge (Get-Date).AddDays(-$ReportAgeDays) }
    if ($exports) {
        Write-Host "    [+] Found $($exports.Count) recent SharpHound export(s) (within last $ReportAgeDays days)." -ForegroundColor Green
    } else {
        Write-Warning "    [-] No recent SharpHound export found (older than $ReportAgeDays days)."
        $Compliant = $false
    }
} else {
    Write-Warning "[-] SharpHound executable NOT found at: $SharpHoundPath"
    $Compliant = $false
}

if ($Compliant) {
    Write-Host "`nStatus: Compliant. Diagnostics tools and recent reports are present." -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nStatus: Non-Compliant. Action required." -ForegroundColor Red
    exit 1
}
