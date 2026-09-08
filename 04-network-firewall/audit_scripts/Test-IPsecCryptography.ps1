# Test-IPsecCryptography.ps1
# Description: Audits IPsec cryptographic proposals, Quick Mode sets, Main Mode sets, PFS enforcement, and global firewall settings.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding()]
param()

Write-Host "Auditing IPsec cryptographic configurations..." -ForegroundColor Cyan

$NonCompliantCount = 0
$WeakEncryptions = @("DES", "DES3", "None")
$WeakHashes = @("MD5", "SHA1", "None")
$WeakDHGroups = @("DH1", "DH2", "None")

# 1. Audit Global Firewall IPsec Settings
Write-Host "Checking Global Firewall IPsec Settings..." -ForegroundColor Yellow
try {
    $FwSetting = Get-NetFirewallSetting -ErrorAction Stop
    if ($null -ne $FwSetting) {
        # Check Certificate Revocation Level
        $CrlLevel = $FwSetting.CertValidationLevel
        if ($CrlLevel -eq "RequireCrlCheck" -or $CrlLevel -eq "AttemptCrlCheck") {
            Write-Host "    - Certificate Revocation Check: $CrlLevel (Compliant)" -ForegroundColor Green
        } else {
            Write-Host "    - Certificate Revocation Check: $CrlLevel (Non-Compliant: should be RequireCrlCheck or AttemptCrlCheck)" -ForegroundColor Red
            $NonCompliantCount++
        }

        # Check ICMP Exemption (ICMP should not be globally exempted without justification)
        if ($FwSetting.Exemptions -match "Icmp") {
            Write-Host "    - Global Exemptions include ICMP (Warning: ICMP bypasses IPsec encapsulation)" -ForegroundColor Yellow
        } else {
            Write-Host "    - Global Exemptions: $($FwSetting.Exemptions) (Compliant)" -ForegroundColor Green
        }

        # Check SA Idle Timeout
        $IdleTime = $FwSetting.MaxSAIdleTimeSeconds
        if ($IdleTime -gt 0 -and $IdleTime -le 300) {
            Write-Host "    - Max SA Idle Time: $($IdleTime)s (Compliant)" -ForegroundColor Green
        } else {
            Write-Host "    - Max SA Idle Time: $IdleTime (Notice: Recommended value is <= 300 seconds)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "    - Warning: Could not query Get-NetFirewallSetting (requires administrative privileges)." -ForegroundColor Yellow
}

# 2. Audit Main Mode Crypto Sets
Write-Host "Checking Main Mode Cryptographic Sets..." -ForegroundColor Yellow
$MMCryptoSets = Get-NetIPsecMainModeCryptoSet -ErrorAction SilentlyContinue

if ($null -eq $MMCryptoSets -or $MMCryptoSets.Count -eq 0) {
    Write-Host "    - No custom Main Mode crypto sets detected. Default OS suites may permit legacy ciphers (Warning)." -ForegroundColor Yellow
} else {
    foreach ($MMSet in $MMCryptoSets) {
        $SetCompliant = $true
        foreach ($Proposal in $MMSet.Proposals) {
            if ($WeakEncryptions -contains $Proposal.Encryption) {
                Write-Host "    - Main Mode Set '$($MMSet.DisplayName)' uses weak encryption: $($Proposal.Encryption) (Non-Compliant)." -ForegroundColor Red
                $SetCompliant = $false
            }
            if ($WeakHashes -contains $Proposal.Hash) {
                Write-Host "    - Main Mode Set '$($MMSet.DisplayName)' uses weak hash: $($Proposal.Hash) (Non-Compliant)." -ForegroundColor Red
                $SetCompliant = $false
            }
            if ($WeakDHGroups -contains $Proposal.KeyExchange) {
                Write-Host "    - Main Mode Set '$($MMSet.DisplayName)' uses weak DH Group: $($Proposal.KeyExchange) (Non-Compliant)." -ForegroundColor Red
                $SetCompliant = $false
            }
        }

        if ($MMSet.MaxMinutes -gt 480) {
            Write-Host "    - Main Mode Set '$($MMSet.DisplayName)' SA lifetime ($($MMSet.MaxMinutes) min) exceeds 480 minutes (Non-Compliant)." -ForegroundColor Red
            $SetCompliant = $false
        }

        if ($SetCompliant) {
            Write-Host "    - Main Mode Set '$($MMSet.DisplayName)': Compliant." -ForegroundColor Green
        } else {
            $NonCompliantCount++
        }
    }
}

# 3. Audit Quick Mode Crypto Sets
Write-Host "Checking Quick Mode Cryptographic Sets..." -ForegroundColor Yellow
$QMCryptoSets = Get-NetIPsecQuickModeCryptoSet -ErrorAction SilentlyContinue

if ($null -eq $QMCryptoSets -or $QMCryptoSets.Count -eq 0) {
    Write-Host "    - No custom Quick Mode crypto sets detected. Connection rules may fall back to default suites (Warning)." -ForegroundColor Yellow
} else {
    foreach ($QMSet in $QMCryptoSets) {
        $SetCompliant = $true

        # Check Perfect Forward Secrecy (PFS)
        $PFS = $QMSet.PerfectForwardSecrecyGroup
        if ($PFS -eq "None" -or $PFS -eq "DH1" -or $PFS -eq "DH2") {
            Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' PFS is disabled or weak: $PFS (Non-Compliant)." -ForegroundColor Red
            $SetCompliant = $false
        } else {
            Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' PFS Group: $PFS (Compliant)." -ForegroundColor Green
        }

        # Check proposals
        foreach ($Proposal in $QMSet.Proposals) {
            if ($Proposal.Encapsulation -ne "ESP") {
                Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' proposal uses encapsulation '$($Proposal.Encapsulation)' (Non-Compliant: ESP required for confidentiality)." -ForegroundColor Red
                $SetCompliant = $false
            }
            if ($WeakEncryptions -contains $Proposal.Encryption) {
                Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' proposal uses weak encryption: $($Proposal.Encryption) (Non-Compliant)." -ForegroundColor Red
                $SetCompliant = $false
            }
            if ($Proposal.Encryption -eq "AES256") {
                if ($Proposal.ESPHash -ne "SHA256" -and $Proposal.ESPHash -ne "SHA384") {
                    Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' AES-256 proposal uses weak ESP hash: $($Proposal.ESPHash) (Non-Compliant)." -ForegroundColor Red
                    $SetCompliant = $false
                }
            } elseif ($Proposal.Encryption -eq "AESGCM256") {
                if ($Proposal.ESPHash -ne "None" -and $Proposal.ESPHash -ne "AESGMAC256") {
                    Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)' AES-GCM proposal specifies invalid hash: $($Proposal.ESPHash) (Warning)." -ForegroundColor Yellow
                }
            }
        }

        if ($SetCompliant) {
            Write-Host "    - Quick Mode Set '$($QMSet.DisplayName)': Compliant." -ForegroundColor Green
        } else {
            $NonCompliantCount++
        }
    }
}

# 4. Audit Connection Security Rules and Main Mode Rules
Write-Host "Checking Connection Security Rule Associations..." -ForegroundColor Yellow
$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue

if ($null -eq $Rules -or $Rules.Count -eq 0) {
    Write-Host "    - No Connection Security Rules found to audit." -ForegroundColor Gray
} else {
    foreach ($Rule in $Rules) {
        # Skip exemption rules where Inbound and Outbound security are None
        if ($Rule.InboundSecurity -eq "None" -and $Rule.OutboundSecurity -eq "None") {
            Write-Host "    - Rule '$($Rule.DisplayName)' is an Exemption rule (Skipping crypto set check)." -ForegroundColor Gray
            continue
        }

        $QMSetName = $Rule.QuickModeCryptoSet
        if ($null -eq $QMSetName -or $QMSetName -eq "") {
            Write-Host "    - Rule '$($Rule.DisplayName)' uses default/unspecified Quick Mode cryptography (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        } else {
            $QMSet = Get-NetIPsecQuickModeCryptoSet -Name $QMSetName -ErrorAction SilentlyContinue
            if ($null -eq $QMSet) {
                Write-Host "    - Rule '$($Rule.DisplayName)' references missing crypto set: $($QMSetName) (Non-Compliant)." -ForegroundColor Red
                $NonCompliantCount++
            } else {
                Write-Host "    - Rule '$($Rule.DisplayName)' bound to Quick Mode set '$($QMSetName)' (Compliant)." -ForegroundColor Green
            }
        }
    }
}

$MMRules = Get-NetIPsecMainModeRule -ErrorAction SilentlyContinue
if ($null -ne $MMRules -and $MMRules.Count -gt 0) {
    foreach ($MMRule in $MMRules) {
        $MMSetName = $MMRule.MainModeCryptoSet
        if ($null -eq $MMSetName -or $MMSetName -eq "") {
            Write-Host "    - Main Mode Rule '$($MMRule.DisplayName)' uses default Main Mode cryptography (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        } else {
            $MMSet = Get-NetIPsecMainModeCryptoSet -Name $MMSetName -ErrorAction SilentlyContinue
            if ($null -eq $MMSet) {
                Write-Host "    - Main Mode Rule '$($MMRule.DisplayName)' references missing crypto set: $($MMSetName) (Non-Compliant)." -ForegroundColor Red
                $NonCompliantCount++
            } else {
                Write-Host "    - Main Mode Rule '$($MMRule.DisplayName)' bound to Main Mode set '$($MMSetName)' (Compliant)." -ForegroundColor Green
            }
        }
    }
}

# Summary and Exit Code
Write-Host "----------------------------------------" -ForegroundColor Cyan
if ($NonCompliantCount -eq 0) {
    Write-Host "IPsec Cryptography Audit: Compliant." -ForegroundColor Green
    exit 0
} else {
    Write-Host "IPsec Cryptography Audit: Non-Compliant ($($NonCompliantCount) issues detected)." -ForegroundColor Red
    exit 1
}
