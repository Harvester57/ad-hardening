# Set-IPsecCryptography.ps1
# Description: Configures local IPsec Main Mode and Quick Mode custom cryptographic configurations.

Write-Host "Configuring hardened IPsec cryptographic settings..." -ForegroundColor Cyan

# Phase 1: Define Main Mode cryptographic proposal
$MMProposal = New-NetIPsecMainModeCryptoProposal -Encryption AES256 -Hash SHA256 -KeyExchange DH19

# Manage Main Mode Crypto Set
$MMSetName = "Hardened_MM_CryptoSet"
$ExistingMM = Get-NetIPsecMainModeCryptoSet -DisplayName $MMSetName -ErrorAction SilentlyContinue

if ($null -eq $ExistingMM) {
    New-NetIPsecMainModeCryptoSet -DisplayName $MMSetName -Proposal $MMProposal | Out-Null
    Write-Host "Created Main Mode crypto set." -ForegroundColor Green
} else {
    Set-NetIPsecMainModeCryptoSet -DisplayName $MMSetName -Proposal $MMProposal | Out-Null
    Write-Host "Updated Main Mode crypto set." -ForegroundColor Gray
}

# Phase 2: Define Quick Mode cryptographic proposal
$QMProposal = New-NetIPsecQuickModeCryptoProposal -Encapsulation ESP -Encryption AES256 -ESPHash SHA256

# Manage Quick Mode Crypto Set
$QMSetName = "Hardened_QM_CryptoSet"
$ExistingQM = Get-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName -ErrorAction SilentlyContinue

if ($null -eq $ExistingQM) {
    New-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName -Proposal $QMProposal | Out-Null
    Write-Host "Created Quick Mode crypto set." -ForegroundColor Green
} else {
    Set-NetIPsecQuickModeCryptoSet -DisplayName $QMSetName -Proposal $QMProposal | Out-Null
    Write-Host "Updated Quick Mode crypto set." -ForegroundColor Gray
}

# Associate sets with all local Connection Security Rules and Main Mode Rules
$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue
if ($null -ne $Rules) {
    foreach ($Rule in $Rules) {
        Set-NetIPsecRule -DisplayName $Rule.DisplayName -QuickModeCryptoSet $QMSetName -ErrorAction SilentlyContinue | Out-Null
    }
}

$MMRules = Get-NetIPsecMainModeRule -ErrorAction SilentlyContinue
if ($null -ne $MMRules) {
    foreach ($MMRule in $MMRules) {
        Set-NetIPsecMainModeRule -DisplayName $MMRule.DisplayName -MainModeCryptoSet $MMSetName -ErrorAction SilentlyContinue | Out-Null
    }
}

Write-Host "IPsec cryptography configuration applied." -ForegroundColor Green
