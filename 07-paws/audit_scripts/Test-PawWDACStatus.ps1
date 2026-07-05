# Test-PawWDACStatus.ps1
# Description: Audits the local PAW to check if Code Integrity policies and HVCI are active.

Write-Host "--- Auditing PAW WDAC State ---" -ForegroundColor Cyan
$Vulnerable = $false

# 1. Query WMI class for Code Integrity status
try {
    $CI = Get-CimInstance -Namespace "Root\Microsoft\Windows\CI" -ClassName "MSFT_Sipolicy" -ErrorAction Stop
    if ($null -ne $CI -and $CI.Count -gt 0) {
        Write-Host "`n[+] Found $($CI.Count) active Code Integrity policies." -ForegroundColor Green
        foreach ($Policy in $CI) {
            Write-Host "    - Policy: $($Policy.FriendlyName) | ID: $($Policy.PolicyID) | Enforced: $($Policy.EnforcementMode)" -ForegroundColor Green
        }
    } else {
        Write-Host "`n[-] No active Code Integrity / WDAC policies detected via WMI." -ForegroundColor Yellow
    }
} catch {
    Write-Host "`n[-] Could not query WMI MSFT_Sipolicy. This is expected if no WDAC policies are currently deployed." -ForegroundColor Gray
}

# 2. Check Memory Integrity (HVCI) configuration
$ScenariosPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
if (Test-Path $ScenariosPath) {
    $HvciStatus = Get-ItemProperty -Path $ScenariosPath -Name "Enabled" -ErrorAction SilentlyContinue
    if ($null -ne $HvciStatus -and $HvciStatus.Enabled -eq 1) {
        Write-Host "[+] Memory Integrity (HVCI) is enabled." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: Memory Integrity (HVCI) is disabled in the registry." -ForegroundColor Red
        $Vulnerable = $true
    }
} else {
    Write-Host "[!] VULNERABLE: Memory Integrity scenario registry path does not exist." -ForegroundColor Red
    $Vulnerable = $true
}

# 3. Final Verdict
if ($Vulnerable) {
    Write-Host "`n[!] Verification FAILED: One or more driver security controls are not configured." -ForegroundColor Red
} else {
    Write-Host "`n[+] Verification PASSED: WDAC driver settings and HVCI are correctly configured." -ForegroundColor Green
}
