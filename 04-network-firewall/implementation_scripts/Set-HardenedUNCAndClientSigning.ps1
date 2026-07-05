# Set-HardenedUNCAndClientSigning.ps1
# Description: Configures Hardened UNC Paths for SYSVOL/NETLOGON, disables insecure guest logons, and enforces LDAP client signing.

Write-Host "Applying network provider and client channel hardening..." -ForegroundColor Cyan

# 1. Hardened UNC Paths configuration
$UNCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
if (-not (Test-Path $UNCPath)) {
    New-Item -Path $UNCPath -Force | Out-Null
}
Set-ItemProperty -Path $UNCPath -Name "\\*\NETLOGON" -Value "RequireIntegrity=1,RequireMutualAuthentication=1" -Type String -ErrorAction Stop
Set-ItemProperty -Path $UNCPath -Name "\\*\SYSVOL" -Value "RequireIntegrity=1,RequireMutualAuthentication=1" -Type String -ErrorAction Stop
Write-Host "[+] Hardened UNC Paths for NETLOGON and SYSVOL configured." -ForegroundColor Green

# 2. Disable Insecure Guest Logons
$LanmanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
if (-not (Test-Path $LanmanPath)) {
    New-Item -Path $LanmanPath -Force | Out-Null
}
Set-ItemProperty -Path $LanmanPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -ErrorAction Stop
Write-Host "[+] Insecure guest logons disabled." -ForegroundColor Green

# 3. Enforce LDAP Client Signing Requirements
$LdapPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
if (-not (Test-Path $LdapPath)) {
    New-Item -Path $LdapPath -Force | Out-Null
}
Set-ItemProperty -Path $LdapPath -Name "LDAPClientIntegrity" -Value 2 -Type DWord -ErrorAction Stop
Write-Host "[+] LDAP Client signing requirement set to Require signing." -ForegroundColor Green
