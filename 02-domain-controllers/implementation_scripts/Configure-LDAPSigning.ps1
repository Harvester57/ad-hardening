# Configure-LDAPSigning.ps1
# Description: Configures the LDAP server signing requirement to Require Signing.

Write-Host "Applying hardening requirement: Enforce LDAP Server Signing..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord
Write-Host "LDAP Server Integrity set to 2 (Require Signing)." -ForegroundColor Green
