# [REQ-NET-005] Harden IPsec Cryptographic Configurations

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, PAWs, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.
* **Baseline Tiering & Sensitivity**:
  * **Tier 0 Domain Controllers & PAWs**: Must strictly enforce modern cryptographic algorithms (AES-256, SHA-256/384, ECDH Group 19/20) with no legacy fallbacks permitted.
  * **Tier 1 Member Servers & Tier 2 Endpoints**: Standard baseline mandates AES-256 and ECDH Group 19/20. Fallback to DH Group 14 (2048-bit MODP) and AES-CBC 256 is permitted solely for systems communicating with legacy appliances or boundary hosts (**[REQ-NET-004]**).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Management Console**:
  * **Main Mode (Key Exchange)**:
    `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]` -> Properties -> **IPsec Settings** -> **IPsec Defaults** -> **Key exchange (Main Mode)** -> Advanced -> Customize
  * **Data Protection (Quick Mode)**:
    `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]` -> Properties -> **IPsec Settings** -> **IPsec Defaults** -> **Data protection (Quick Mode)** -> Advanced -> Customize
  * **Authentication Methods**:
    `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]` -> Properties -> **IPsec Settings** -> **IPsec Defaults** -> **Authentication method** -> Advanced -> Customize
  * **IPsec Exemptions**:
    `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]` -> Properties -> **IPsec Settings** -> **IPsec exemptions** -> **Exempt ICMP from IPsec**: `No`
* **Registry & Policy Stores**:
  * **Group Policy WStore**: `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\WStore`
  * **Local Policy Store**: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System`
  * **Global IPsec Settings**: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\Global`
* **Command-Line Interface (netsh)**:
  * `netsh advfirewall set global mainmode mmsecmethods ecdhp256:aes256-sha256,ecdhp384:aes256-sha384,dhgroup14:aes256-sha256 mmkeylifetime 480min,0sess mmforcedh yes`
  * `netsh advfirewall set global ipsec strongcrlcheck 1 saidletimemin 5 defaultexemptions neighbordiscovery,dhcp`

---

## Rationale
Internet Protocol Security (IPsec) is the foundational cryptographic framework that underpins domain isolation (**[REQ-NET-004]**) and line-encryption across Active Directory networks. However, default IPsec settings in legacy Windows environments permit outdated cryptographic primitives, including 3DES, DES, MD5, SHA-1, and Diffie-Hellman Groups 1, 2, and 5. These algorithms are mathematically broken or provide insufficient security margins against modern adversaries.

Hardening IPsec cryptographic parameters mitigates multiple specific threat vectors:

### 1. 64-Bit Block Cipher Vulnerabilities (Sweet32 / CVE-2016-2183)
Triple-DES (3DES) and legacy DES utilize a 64-bit block size ($L = 64$). Due to the birthday paradox, collisions among ciphertext blocks encrypted under the same key become probable after approximately $2^{L/2} = 2^{32}$ blocks, corresponding to only 32 gigabytes of transmitted data. In high-bandwidth Active Directory environments—such as directory replication between Domain Controllers, file transfers over SMB, or administrative remote management—an eavesdropper can passively capture traffic and recover sensitive plaintext tokens, HTTP session cookies, or directory attributes. Restricting IPsec to the Advanced Encryption Standard (AES) with a 128-bit block size ($L = 128$) moves the collision threshold to $2^{64}$ blocks (exabytes of data), completely eliminating collision-based key recovery attacks.

### 2. Weak Diffie-Hellman Groups & Logjam Attacks
Legacy Diffie-Hellman groups rely on standard prime fields that are too small for modern computational capabilities:
* **DH Group 1 (768-bit MODP)** and **DH Group 2 (1024-bit MODP)**: Vulnerable to precomputation attacks using the Number Field Sieve (NFS). Adversaries can precompute discrete logarithm tables for standard primes, enabling real-time passive eavesdropping and active Man-in-the-Middle (MitM) decryption of IKE/AuthIP Main Mode negotiations.
* **DH Group 5 (1536-bit MODP)**: Provides approximately 96 bits of symmetric security equivalence, falling below the mandatory 128-bit security floor.

Mandating Elliptic Curve Diffie-Hellman (ECDH) **Group 19 (NIST P-256)** and **Group 20 (NIST P-384)** provides 128-bit and 192-bit security equivalence respectively, dramatically outperforming discrete-logarithm groups in both computational speed and cryptographic resilience. DH Group 14 (2048-bit MODP) provides a 112-bit security margin and is permitted only as a compatibility fallback for legacy hardware appliances.

### 3. Hash Collision & Pre-Image Exploits (MD5 and SHA-1)
Demonstrated collision attacks against MD5 (practical chosen-prefix collisions) and SHA-1 (SHAttered and Shambles attacks) allow adversaries to generate forged cryptographic certificates and manipulate packet authentication without detection. In IPsec negotiations and integrity verification, compromised hash functions undermine data authenticity and enable protocol downgrade attacks. Restricting Phase 1 and Phase 2 integrity to SHA-256 and SHA-384 ensures mathematical collision resistance and integrity protection.

### 4. Authenticated Encryption with Associated Data (AEAD) via AES-GCM
Traditional IPsec configurations employ AES in Cipher Block Chaining (CBC) mode paired with an HMAC-SHA integrity check. This architecture requires two distinct cryptographic operations over each packet (encrypt then MAC) and can expose endpoints to padding oracle attacks if padding verification is improperly implemented.

Windows Server 2016 and Windows 10 support **AES-GCM (Galois/Counter Mode, RFC 4106)**. AES-GCM is an Authenticated Encryption with Associated Data (AEAD) cipher that performs encryption and integrity authentication (via GMAC) simultaneously in a single pass. Utilizing hardware-accelerated CPU instructions (Intel AES-NI / AMD-V), AES-GCM delivers wire-speed 10Gbps+ throughput while eliminating padding oracle vectors.

### 5. Perfect Forward Secrecy (PFS) in Quick Mode
By default, Windows IPsec derives Quick Mode (Phase 2) data protection keys directly from the key material established during Main Mode (Phase 1) negotiation. If an attacker captures encrypted traffic and subsequently compromises an endpoint's private key or Main Mode session key, they can retroactively decrypt all historical sessions.

Enforcing **Perfect Forward Secrecy (PFS)** mandates an independent Diffie-Hellman exchange during each Quick Mode rekey. Even if a Main Mode key or long-term private key is compromised, previously captured Quick Mode session traffic cannot be decrypted.

### 6. Security Association Lifetimes and Replay Protection
Prolonged Security Association (SA) lifetimes expose cipher keys to cryptanalytic wear and increase the observation window for replay attacks. Setting Main Mode lifetimes to 480 minutes (8 hours) and Quick Mode lifetimes to 100,000 KB (100 MB) or 60 minutes forces periodic rekeying, resetting packet sequence counters and limiting the cryptanalytic value of any intercepted key material.

### 7. Certificate Revocation List (CRL) Validation
When certificate-based authentication is configured for IPsec domain isolation, endpoints that do not check revocation status will accept connections from compromised or decommissioned machines. Enforcing `RequireCrlCheck` guarantees that revoked machine certificates cannot establish IPsec Security Associations.

---

## Legacy Impact & Compatibility
* **Legacy Windows Operating Systems**:
  Windows 7 and Windows Server 2008 R2 do not natively support ECDH Group 19/20 or AES-GCM without specific hotfixes (KB2928562 / KB3081320). In multi-tier environments containing legacy hosts, ensure those machines are upgraded or assigned to an explicit Boundary Group that negotiates DH Group 14 (2048-bit) and AES-CBC 256.
* **Network Middleboxes, Routers, and Firewalls**:
  Network routing equipment and packet inspection firewalls separating domain subnets must permit IPsec transport traffic:
  * **UDP Port 500 (IKE)**: Phase 1 key exchange.
  * **UDP Port 4500 (NAT-T)**: IKE and ESP encapsulated across Network Address Translation.
  * **IP Protocol 50 (ESP)**: Encapsulating Security Payload for encrypted data transfer.
* **Path MTU Discovery (PMTUD), Packet Overhead, and MSS Clamping**:
  IPsec Transport Mode encapsulation adds an ESP header, Initialization Vector (IV), padding, ESP trailer, and Integrity Check Value (ICV), increasing the packet size by 50 to 70+ bytes (plus an additional 8 bytes if UDP port 4500 NAT-T encapsulation is used). This reduces the effective Maximum Transmission Unit (MTU) from standard 1500 bytes to approximately 1420–1440 bytes.
  * If intermediate routers or edge firewalls drop ICMP Type 3 Code 4 ("Destination Unreachable - Fragmentation Needed") messages, PMTU Discovery fails ("Black Hole" routers), causing large TCP packets (such as SMB file transfers or Kerberos tickets with PACs) to hang indefinitely.
  * **Remediation**: Ensure ICMP Type 3 Code 4 is permitted across all network firewalls, or configure TCP Maximum Segment Size (MSS) clamping (e.g., clamping MSS to 1380–1400 bytes) on edge routers.
* **Hardware Offloading (IPsec Task Offload - IPsecTO)**:
  Modern Physical and Virtual Network Interface Cards (NICs) support IPsec Task Offload to offload cryptographic encryption and hashing from the CPU. If IPsec throughput bottlenecks occur, verify that `Enable-NetAdapterIPsecOffload` is enabled and that CPU virtualization settings pass through AES-NI instructions.
* **BitLocker Network Unlock & DHCP Exemptions**:
  Pre-boot authentication via BitLocker Network Unlock relies on cleartext DHCP broadcasts (UDP ports 67 and 68) from the UEFI firmware stack before the operating system kernel and IPsec drivers load. Ensure that DHCP traffic is exempted from IPsec encapsulation (`Set-NetFirewallSetting -Exemptions NeighborDiscovery,Dhcp`), and that Windows Deployment Services (WDS) Network Unlock servers are placed in boundary exemption rules (**[REQ-NET-004]**).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Open the GPO Editor
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting the target systems (e.g., `GPO_Hardening_IPsec_Cryptography`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Windows Defender Firewall with Advanced Security - [LDAP]`
4. Right-click **Windows Defender Firewall with Advanced Security - [LDAP]** and select **Properties**.
5. Select the **IPsec Settings** tab.

#### 2. Configure Key Exchange (Main Mode) Settings
1. Under **IPsec defaults**, click **Customize...**
2. Under **Key exchange (Main Mode)**, select **Advanced**, then click **Customize...**
3. Configure the **Security methods** list in priority order:
   * **Proposal 1 (Preferred)**:
     * **Integrity**: `SHA-256`
     * **Encryption**: `AES-256`
     * **Key exchange algorithm**: `Elliptic Curve Diffie-Hellman Group 19` (P-256)
   * **Proposal 2**:
     * **Integrity**: `SHA-384`
     * **Encryption**: `AES-256`
     * **Key exchange algorithm**: `Elliptic Curve Diffie-Hellman Group 20` (P-384)
   * **Proposal 3 (Compatibility Fallback)**:
     * **Integrity**: `SHA-256`
     * **Encryption**: `AES-256`
     * **Key exchange algorithm**: `Diffie-Hellman Group 14` (2048-bit)
   * *Remove all entries referencing DES, 3DES, MD5, SHA-1, or DH Groups 1, 2, and 5.*
4. Under **Key lifetimes**:
   * **Minutes**: Set to `480` (8 hours).
   * **Sessions**: Set to `0` (unlimited within time window).
5. Under **Diffie-Hellman**:
   * Select **Force Diffie-Hellman** (ensures DH recalculation upon rekeying).
6. Click **OK**.

#### 3. Configure Data Protection (Quick Mode) Settings
1. Under **Data protection (Quick Mode)**, select **Advanced**, then click **Customize...**
2. Check **Require encryption for all connection security rules that use these settings**.
3. Configure the **Data integrity and encryption** rules:
   * **Rule 1 (AEAD Preferred)**:
     * **Protocol**: `ESP`
     * **Encryption**: `AES-GCM 256`
     * **Integrity**: `None` (GMAC is integrated directly into GCM mode)
   * **Rule 2 (Standard CBC)**:
     * **Protocol**: `ESP`
     * **Encryption**: `AES-256`
     * **Integrity**: `SHA-256`
   * *Remove any entries referencing DES, 3DES, MD5, or SHA-1.*
4. Under **Key lifetimes**:
   * **Data amount**: Set to `100000` KB (100 MB).
   * **Time**: Set to `60` minutes.
5. Under **Perfect Forward Secrecy (PFS)**:
   * Check **Use Diffie-Hellman for data protection (PFS)**.
   * **Key exchange algorithm**: Select `Elliptic Curve Diffie-Hellman Group 19` (or `Same as Main Mode`).
6. Click **OK**.

#### 4. Configure Authentication Method Defaults
1. Under **Authentication method**, select **Advanced**, then click **Customize...**
2. Configure authentication priorities:
   * **First authentication method**: Select **Computer (Kerberos V5)** (Standard for domain-joined hosts).
   * **Second authentication method / Fallback**: Select **Computer certificate**, specify the enterprise Root/Intermediate CA, and configure criteria to match machine certificates (RSA >= 3072 bits or ECDSA P-256).
   * *Ensure Pre-Shared Key (PSK) authentication is strictly prohibited in enterprise production environments.*
3. Click **OK**.

#### 5. Configure Global IPsec Exemptions and Certificate Validation
1. Under **IPsec exemptions**:
   * **Exempt ICMP from IPsec**: Select `No` (dictates that ICMP traffic must be authenticated and encrypted along with standard traffic, closing covert channels).
2. Click **OK** to close the IPsec Defaults dialog.
3. Click **Apply**, then **OK** on the Windows Defender Firewall Properties window.

---

## Option B: PowerShell & CLI Configuration (Remediation / Non-GPO)

Use the following scripts and commands to configure hardened IPsec cryptographic parameters locally or across headless / non-domain environments.

### Remediation Script:
[Download Script: Set-IPsecCryptography.ps1](implementation_scripts/Set-IPsecCryptography.ps1)

```powershell
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
```

### CLI Remediation (netsh advfirewall):
To configure global IPsec cryptographic baselines on systems where PowerShell is restricted:

```cmd
:: 1. Configure Main Mode cryptographic proposals (ECDH P-256 / P-384 / DH14, AES-256, SHA-256/384)
netsh advfirewall set global mainmode mmsecmethods ecdhp256:aes256-sha256,ecdhp384:aes256-sha384,dhgroup14:aes256-sha256 mmkeylifetime 480min,0sess mmforcedh yes

:: 2. Enforce strict certificate revocation checking and limit SA idle time
netsh advfirewall set global ipsec strongcrlcheck 1 saidletimemin 5 defaultexemptions neighbordiscovery,dhcp
```

### Audit Script:
[Download Script: Test-IPsecCryptography.ps1](audit_scripts/Test-IPsecCryptography.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (IPsec transport mode for domain isolation)
* **ANSSI General Security Rules (RGS)**: Annex B1 (Rules on Cryptographic Mechanisms - Key lengths, symmetric encryption, and hashing algorithms)
* **NIST Special Publication 800-131A Rev. 2**: Transitions: Recommendation for Transitioning the Use of Cryptographic Algorithms and Key Lengths
* **NIST Special Publication 800-77 Rev. 1**: Guide to IPsec VPNs
* **NSA Commercial National Security Algorithm (CNSA) Suite**: Cryptographic Security Criteria for IPsec
* **CIS Windows Server 2016 / 2019 / 2022 Benchmarks**: Section 19 (Windows Defender Firewall with Advanced Security)
