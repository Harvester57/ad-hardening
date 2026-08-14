# Get-PawAccountCachedLogonsStatus.ps1
Write-Host "--- Auditing PAW Cached Logons and PBKDF2 Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit CachedLogonsCount
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$CacheCount = (Get-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount
if ($CacheCount -ne 0) {
    Write-Host "    [!] VULNERABLE: CachedLogonsCount is '$CacheCount' (Expected: 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] CachedLogonsCount: 0" -ForegroundColor Green
}

# 2. Audit NL$IterationCount
$CachePath = "HKLM:\SECURITY\Cache"
$IterCount = (Get-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -ErrorAction SilentlyContinue)."NL`$IterationCount"
if ($IterCount -ne 1954) {
    Write-Host "    [!] VULNERABLE: NL`$IterationCount is '$IterCount' (Expected: 1954)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] NL`$IterationCount: 1954" -ForegroundColor Green
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
