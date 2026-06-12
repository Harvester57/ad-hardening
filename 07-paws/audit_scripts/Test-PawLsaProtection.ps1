# Test-PawLsaProtection.ps1
# Description: Checks the registry settings and running process state to verify LSA Protection is active.

Write-Host "--- Auditing LSA Protection Status ---" -ForegroundColor Cyan

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RunAsPPL = (Get-ItemProperty -Path $LsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

if ($RunAsPPL -eq 1) {
    Write-Host "    - LSA Protection (RunAsPPL): Enabled (Secure)" -ForegroundColor Green
} else {
    Write-Host "    - VULNERABLE: LSA Protection (RunAsPPL) is not configured or disabled (Value: $($RunAsPPL))" -ForegroundColor Red
}
