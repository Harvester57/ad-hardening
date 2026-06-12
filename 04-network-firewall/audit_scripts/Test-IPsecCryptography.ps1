# Test-IPsecCryptography.ps1
# Description: Checks that IPsec rules only utilize strong cryptographic sets.

Write-Host "Auditing IPsec cryptographic configurations..." -ForegroundColor Cyan

$NonCompliantCount = 0
$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue

if ($null -eq $Rules -or $Rules.Count -eq 0) {
    Write-Host "    - No IPsec rules found to audit." -ForegroundColor Gray
} else {
    foreach ($Rule in $Rules) {
        $QMSetName = $Rule.QuickModeCryptoSet
        if ($null -eq $QMSetName -or $QMSetName -eq "") {
            Write-Host "    - Rule '$($Rule.DisplayName)' is using default/unconfigured Quick Mode cryptography (Non-Compliant)." -ForegroundColor Red
            $NonCompliantCount++
        } else {
            $QMSet = Get-NetIPsecQuickModeCryptoSet -Name $QMSetName -ErrorAction SilentlyContinue
            if ($null -eq $QMSet) {
                Write-Host "    - Rule '$($Rule.DisplayName)' references non-existent crypto set: $($QMSetName) (Non-Compliant)." -ForegroundColor Red
                $NonCompliantCount++
            } else {
                $Compliant = $true
                foreach ($Proposal in $QMSet.Proposals) {
                    if ($Proposal.Encryption -ne "AES256" -and $Proposal.Encryption -ne "AESGCM256") {
                        $Compliant = $false
                    }
                    if ($Proposal.ESPHash -ne "SHA256" -and $Proposal.ESPHash -ne "SHA384") {
                        $Compliant = $false
                    }
                }
                
                if ($Compliant) {
                    Write-Host "    - Rule '$($Rule.DisplayName)' matches cryptographic standards (Compliant)." -ForegroundColor Green
                } else {
                    Write-Host "    - Rule '$($Rule.DisplayName)' uses weak encryption or hashing methods (Non-Compliant)." -ForegroundColor Red
                    $NonCompliantCount++
                }
            }
        }
    }
}

if ($NonCompliantCount -eq 0) {
    Write-Host "IPsec Cryptography Audit: Compliant." -ForegroundColor Green
} else {
    Write-Host "IPsec Cryptography Audit: Non-Compliant." -ForegroundColor Red
}
