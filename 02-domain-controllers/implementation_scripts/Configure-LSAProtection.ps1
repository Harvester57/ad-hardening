# Configure-LSAProtection.ps1
# Description: Enables LSA Protection (RunAsPPL) in the registry.

Write-Host "Applying hardening requirement: Enable LSA Protection..." -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "LSA Protection registry configuration applied. A reboot is required to activate." -ForegroundColor Green
