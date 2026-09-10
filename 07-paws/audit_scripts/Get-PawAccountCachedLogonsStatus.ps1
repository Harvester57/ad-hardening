# Get-PawAccountCachedLogonsStatus.ps1
# Description: Audits cached logons count and PBKDF2 iteration count on PAWs.

Write-Host "--- Auditing PAW Cached Logons and PBKDF2 Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit CachedLogonsCount
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path -Path $WinlogonPath)) {
    Write-Host "    [!] MISSING KEY: $WinlogonPath" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    $CacheCount = (Get-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -ErrorAction SilentlyContinue).CachedLogonsCount
    if ($CacheCount -ne 0) {
        Write-Host "    [!] VULNERABLE: CachedLogonsCount is '$CacheCount' (Expected: 0)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] CachedLogonsCount: 0 (Secure - Cache Disabled)" -ForegroundColor Green
    }
}

# 2. Audit NL$IterationCount
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path -Path $CachePath)) {
    Write-Host "    [!] MISSING KEY: $CachePath" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    $IterCount = (Get-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -ErrorAction SilentlyContinue)."NL`$IterationCount"
    if ($IterCount -ne 1954) {
        Write-Host "    [!] VULNERABLE: NL`$IterationCount is '$IterCount' (Expected: 1954)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] NL`$IterationCount: 1954 (Secure - ~2M PBKDF2 Iterations)" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
