# Configure-DisableNTLMv1.ps1
# Description: Restricts NTLM authentication to NTLMv2 and refuses NTLMv1 / LM.

Write-Host "Applying hardening requirement: Disable NTLMv1..." -ForegroundColor Cyan

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Host "LM Compatibility Level set to 5 (Send NTLMv2 response only. Refuse LM & NTLM)." -ForegroundColor Green
