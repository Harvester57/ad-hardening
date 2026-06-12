# Hardening Requirement: Harden IPsec Cryptographic Configurations

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, PAWs, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]` (Properties -> IPsec Settings -> IPsec Defaults -> Customize)

---

## Rationale
Default IPsec configurations in older Windows deployments or standard configurations allow weak encryption and integrity algorithms (such as 3DES, DES, MD5, SHA-1, and Diffie-Hellman Groups 1, 2, or 5). These legacy algorithms are vulnerable to key recovery attacks, pre-computation table attacks, and cryptographic collisions.

To maintain secure communications through 2030 and beyond, IPsec configurations must be restricted to modern cryptographic standards. Utilizing Advanced Encryption Standard (AES-256) and Elliptic Curve Diffie-Hellman (ECDH) Group 19 (256-bit) or Group 20 (384-bit) provides strong mathematical protection against decryption and ensures perfect forward secrecy (PFS). Mandating these suites prevents protocol downgrade attacks and secures sensitive domain replication and management traffic.

---

## Legacy Impact & Compatibility
* **Legacy OS Support**: Outdated operating systems (such as Windows 7, Windows Server 2008 R2, or old Linux kernels that do not support modern DH groups or AES-256) will fail to establish IPsec security associations (SAs). Ensure all domain member systems are upgraded to supported OS versions before applying this policy.
* **Non-Domain / Third-Party Appliances**: Network devices, storage systems, and Linux servers that communicate within the IPsec domain boundary must support these strong suites. If they do not, they must be added to the IPsec exemption list (Boundary Group) to maintain cleartext communications.
* **Performance Impact**: Modern CPUs include hardware acceleration (AES-NI) for AES encryption, meaning the performance overhead of moving from AES-128 or 3DES to AES-256 is negligible.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_IPsec_Cryptography`) targeting the appropriate Organizational Units.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]`
4. Right-click **Windows Defender Firewall with Advanced Security - [LDAP]** and select **Properties**.
5. Select the **IPsec Settings** tab.
6. Under **IPsec defaults**, click **Customize...**
7. Under **Key exchange (Main Mode)**, select **Advanced** and click **Customize...**
8. Configure the security methods:
   * Remove any entries referencing SHA-1, MD5, 3DES, DES, or DH Groups 1, 2, or 5.
   * Add or reorder methods so the preferred method is first:
     * **Encryption**: `AES-256`
     * **Integrity**: `SHA-256` or `SHA-384`
     * **Key exchange algorithm**: `Elliptic Curve Diffie-Hellman Group 19` (or `Group 20`)
   * Note: You may keep `Diffie-Hellman Group 14` (2048-bit) as a lower-priority fallback option for older active systems if required.
9. Click **OK**.
10. Under **Data protection (Quick Mode)**, select **Advanced** and click **Customize...**
11. Check **Require encryption for all connection security rules that use these settings**.
12. Configure the data integrity and encryption rules:
    * Remove any rules using SHA-1, MD5, 3DES, or DES.
    * Add a custom rule:
      * **Protocol**: `ESP`
      * **Encryption**: `AES-256` (or `AES-GCM 256`)
      * **Integrity**: `SHA-256` (or `None` if utilizing GCM mode)
13. Click **OK** on all dialog boxes to save the configurations.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure custom cryptographic sets on individual systems.

#### Remediation Script:
[Download Script: Set-IPsecCryptography.ps1](implementation_scripts/Set-IPsecCryptography.ps1)

```powershell
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
```

#### Audit Script:
[Download Script: Test-IPsecCryptography.ps1](audit_scripts/Test-IPsecCryptography.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (IPsec transport mode for domain isolation)
* **ANSSI General Security Rules (RGS)**: Annex B1 (Cryptographic mechanisms)
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **NIST Special Publication 800-131A**: Transitions to Stronger Cryptographic Algorithms
