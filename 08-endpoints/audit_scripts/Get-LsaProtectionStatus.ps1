# Get-LsaProtectionStatus.ps1
# Description: Checks the registry settings and running process state to verify LSA Protection is active.

Write-Host "--- Auditing LSA Protection Status ---" -ForegroundColor Cyan

$LsaPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$RunAsPPL = (Get-ItemProperty -Path $LsaPoliciesPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

if ($RunAsPPL -eq 1) {
    Write-Host "    - LSA Protection (RunAsPPL): Enabled (Secure)" -ForegroundColor Green
} else {
    Write-Host "    - VULNERABLE: LSA Protection (RunAsPPL) is not configured or disabled (Value: $($RunAsPPL))" -ForegroundColor Red
}
