# Get-NTLMv1Status.ps1
# Description: Audits the LM Compatibility Level setting in the registry.

Write-Host "--- Auditing NTLMv1 Restriction ---" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $lmVal = $lsaReg.LmCompatibilityLevel
    if ($lmVal -eq 5) {
        Write-Host "[+] NTLMv1 is disabled. LM Compatibility Level is set to $($lmVal) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LM Compatibility Level is set to $($lmVal) (Required: 5)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LmCompatibilityLevel key is missing. System is using the default value (allows NTLMv1)." -ForegroundColor Red
}
