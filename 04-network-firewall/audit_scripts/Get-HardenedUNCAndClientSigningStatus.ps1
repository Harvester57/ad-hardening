# Get-HardenedUNCAndClientSigningStatus.ps1
# Description: Audits the registry configuration of Hardened UNC Paths, Lanman guest authentication, and LDAP Client signing.

Write-Host "--- Auditing Hardened UNC Paths and Client Signing status ---" -ForegroundColor Cyan

# 1. Audit UNC Paths
$UNCPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
if (Test-Path $UNCPath) {
    $NetlogonVal = Get-ItemProperty -Path $UNCPath -Name "\\*\NETLOGON" -ErrorAction SilentlyContinue
    $SysvolVal = Get-ItemProperty -Path $UNCPath -Name "\\*\SYSVOL" -ErrorAction SilentlyContinue
    
    $NetColor = if ($NetlogonVal -and $NetlogonVal.'\\*\NETLOGON' -eq "RequireIntegrity=1,RequireMutualAuthentication=1") { "Green" } else { "Red" }
    $SysColor = if ($SysvolVal -and $SysvolVal.'\\*\SYSVOL' -eq "RequireIntegrity=1,RequireMutualAuthentication=1") { "Green" } else { "Red" }
    
    Write-Host "    - Hardened UNC NETLOGON: $($NetlogonVal.'\\*\NETLOGON') (Expected: RequireIntegrity=1,RequireMutualAuthentication=1)" -ForegroundColor $NetColor
    Write-Host "    - Hardened UNC SYSVOL:   $($SysvolVal.'\\*\SYSVOL') (Expected: RequireIntegrity=1,RequireMutualAuthentication=1)" -ForegroundColor $SysColor
} else {
    Write-Host "    - Hardened UNC registry path: NOT FOUND" -ForegroundColor Red
}

# 2. Audit Guest Logons
$LanmanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$GuestVal = Get-ItemProperty -Path $LanmanPath -Name "AllowInsecureGuestAuth" -ErrorAction SilentlyContinue
$GuestSetting = if ($GuestVal) { $GuestVal.AllowInsecureGuestAuth } else { 1 }
$GuestColor = if ($GuestSetting -eq 0) { "Green" } else { "Red" }
Write-Host "    - Allow Insecure Guest Logons: $GuestSetting (Expected: 0)" -ForegroundColor $GuestColor

# 3. Audit LDAP Client Signing
$LdapPath = "HKLM:\System\CurrentControlSet\Services\LDAP"
$LdapVal = Get-ItemProperty -Path $LdapPath -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue
$LdapSetting = if ($LdapVal) { $LdapVal.LDAPClientIntegrity } else { 0 }
$LdapColor = if ($LdapSetting -eq 2) { "Green" } else { "Red" }
Write-Host "    - LDAP Client Integrity (Signing): $LdapSetting (Expected: 2 - Require)" -ForegroundColor $LdapColor
