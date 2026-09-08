# Set-IPsecCryptography.ps1
# Description: Configures hardened IPsec Main Mode, Quick Mode, and Global Firewall cryptographic parameters.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding()]
param()

Write-Host "Configuring hardened IPsec cryptographic settings..." -ForegroundColor Cyan

# Phase 1: Define Main Mode cryptographic proposals
# Proposals mandate AES-256 encryption, SHA-256/SHA-384 hashing, and ECDH Group 19/20 or DH14 key exchange.
# Weak suites (DES, 3DES, MD5, SHA-1, DH Groups 1, 2, 5) are strictly excluded.
$MMProposals = @(
    (New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA256 -KeyExchange DH19),
    (New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA384 -KeyExchange DH20),
    (New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA256 -KeyExchange DH14)
)

# Manage Main Mode Crypto Set
$MMSetName = "Hardened_MM_CryptoSet"
$ExistingMM = Get-NetIPsecMainModeCryptoSet -DisplayName $MMSetName -ErrorAction SilentlyContinue

if ($null -eq $ExistingMM) {
    New-NetIPsecMainModeCryptoSet -DisplayName $MMSetName `
        -Proposal $MMProposals `
        -MaxMinutes 480 `
        -MaxSessions 0 `
        -ForceDiffieHellman $true | Out-Null
    Write-Host "Created Main Mode crypto set '$($MMSetName)'." -ForegroundColor Green
} else {
    Set-NetIPsecMainModeCryptoSet -DisplayName $MMSetName `
        -Proposal $MMProposals `
        -MaxMinutes 480 `
        -MaxSessions 0 `
        -ForceDiffieHellman $true | Out-Null
    Write-Host "Updated Main Mode crypto set '$($MMSetName)'." -ForegroundColor Gray
}

# Phase 2: Define Quick Mode cryptographic proposals
# Primary: ESP AES-GCM 256 (Authenticated Encryption with Associated Data - AEAD)
# Secondary: ESP AES-256 with SHA-256 integrity
$QMProposals = @(
    (New-NetIPsecQuickModeCryptoProposal -Encapsulation ESP -Encryption AESGCM256 -ESPHash None -MaxKilobytes 100000 -MaxMinutes 60),
    (New-NetIPsecQuickModeCryptoProposal -Encapsulation ESP -Encryption AES256 -ESPHash SHA256 -MaxKilobytes 100000 -MaxMinutes 60)
)

# Manage Quick Mode Crypto Set with Perfect Forward Secrecy (PFS) enforced
$QMSetName = "Hardened_QM_CryptoSet"
$ExistingQM = Get-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName -ErrorAction SilentlyContinue

if ($null -eq $ExistingQM) {
    New-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName `
        -Proposal $QMProposals `
        -PerfectForwardSecrecyGroup DH19 | Out-Null
    Write-Host "Created Quick Mode crypto set '$($QMSetName)' with PFS (DH19)." -ForegroundColor Green
} else {
    Set-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName `
        -Proposal $QMProposals `
        -PerfectForwardSecrecyGroup DH19 | Out-Null
    Write-Host "Updated Quick Mode crypto set '$($QMSetName)' with PFS (DH19)." -ForegroundColor Gray
}

# Phase 3: Configure Global IPsec Firewall Settings
# Enforces CRL revocation checking for computer certificates, bounds idle time, and restricts exemptions.
try {
    Set-NetFirewallSetting -CertValidationLevel RequireCrlCheck `
        -MaxSAIdleTimeSeconds 300 `
        -Exemptions NeighborDiscovery,Dhcp `
        -ErrorAction Stop | Out-Null
    Write-Host "Configured global firewall IPsec settings (RequireCrlCheck, IdleTime: 300s, Exemptions: ND/DHCP)." -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not update global firewall settings: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Phase 4: Associate cryptographic sets with local Connection Security Rules and Main Mode Rules
$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue
if ($null -ne $Rules -and $Rules.Count -gt 0) {
    foreach ($Rule in $Rules) {
        # Only bind QuickModeCryptoSet if the rule is not an Exemption rule (InboundSecurity -ne None)
        if ($Rule.InboundSecurity -ne "None" -or $Rule.OutboundSecurity -ne "None") {
            Set-NetIPsecRule -DisplayName $Rule.DisplayName -QuickModeCryptoSet $QMSetName -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Associated '$($QMSetName)' with rule '$($Rule.DisplayName)'." -ForegroundColor Gray
        }
    }
} else {
    Write-Host "No active Connection Security Rules found to bind." -ForegroundColor Gray
}

$MMRules = Get-NetIPsecMainModeRule -ErrorAction SilentlyContinue
if ($null -ne $MMRules -and $MMRules.Count -gt 0) {
    foreach ($MMRule in $MMRules) {
        Set-NetIPsecMainModeRule -DisplayName $MMRule.DisplayName -MainModeCryptoSet $MMSetName -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Associated '$($MMSetName)' with Main Mode rule '$($MMRule.DisplayName)'." -ForegroundColor Gray
    }
} else {
    Write-Host "No active Main Mode Rules found to bind." -ForegroundColor Gray
}

Write-Host "IPsec cryptography hardening applied successfully." -ForegroundColor Green
