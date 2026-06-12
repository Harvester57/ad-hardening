# Get-LSAProtectionStatus.ps1
# Description: Audits LSA Protection (RunAsPPL) in the registry.

Write-Host "--- Auditing LSA Protection ---" -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$lsaReg = Get-ItemProperty -Path $regPath -Name "RunAsPPL" -ErrorAction SilentlyContinue

if ($lsaReg) {
    $pplVal = $lsaReg.RunAsPPL
    if ($pplVal -eq 1) {
        Write-Host "[+] LSA Protection is enabled. RunAsPPL is set to $($pplVal) (Secure)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: RunAsPPL is set to $($pplVal) (Required: 1)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: RunAsPPL registry value is missing. LSA is not running as a protected process." -ForegroundColor Red
}
