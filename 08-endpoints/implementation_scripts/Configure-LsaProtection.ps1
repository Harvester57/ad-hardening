# Configure-LsaProtection.ps1
# Description: Configures the RunAsPPL registry key to enable LSA Protection on workstations.

Write-Host "Applying LSA Protection registry hardening..." -ForegroundColor Cyan

$LsaPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

if (-not (Test-Path $LsaPoliciesPath)) {
    New-Item -Path $LsaPoliciesPath -Force | Out-Null
}

Set-ItemProperty -Path $LsaPoliciesPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "[+] LSA Protection (RunAsPPL) enabled in registry policies. (Reboot required)." -ForegroundColor Green
