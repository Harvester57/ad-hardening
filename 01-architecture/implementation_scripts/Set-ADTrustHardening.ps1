# Set-ADTrustHardening.ps1
# Description: Hardens trust relationships by disabling SID History and TGT Delegation, and enabling Quarantine.

Write-Host "Applying hardening requirement: Harden Active Directory Domain Trusts..." -ForegroundColor Cyan

# Set target trust variables (replace with your domain names)
$TrustingDomain = "corp.local"
$TrustedDomain = "partner.local"

# 1. Disable SID History on Forest/External Trust
Write-Host "Disabling SID History on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /EnableSIDHistory:no

# 2. Enable Quarantine (SID Filtering) on External Domain Trust
Write-Host "Enabling Quarantine on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /Quarantine:yes

# 3. Disable TGT Delegation over Inbound Trust
Write-Host "Disabling Kerberos TGT Delegation on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /EnableTGTDelegation:no

Write-Host "Trust hardening commands executed." -ForegroundColor Green
