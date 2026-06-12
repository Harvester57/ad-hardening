# Configure-LDAPChannelBinding.ps1
# Description: Enforces LDAP Channel Binding Token requirements to Always.

Write-Host "Applying hardening requirement: Enforce LDAP Channel Binding..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
Write-Host "LDAP Channel Binding requirements set to 2 (Always)." -ForegroundColor Green
