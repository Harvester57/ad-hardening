# [REQ-DC-010] Restrict Kerberos Encryption Types

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Network security: Configure encryption types allowed for Kerberos`
  * **Setting**: `AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types` (Ensure `DES_CBC_CRC`, `DES_CBC_MD5`, and `RC4_HMAC_MD5` are unchecked)
  * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` -> `SupportedEncryptionTypes` = `2147483640` (REG_DWORD, decimal representation of `0x7FFFFFF8` which enables AES128, AES256, and Future encryption types while explicitly disallowing DES and RC4) or `2147483584` (`0x7FFFFFC0` which restricts strictly to AES256 and Future encryption types)

### Kerberos Encryption Types Bitmask Reference

The `SupportedEncryptionTypes` policy is evaluated as a bitmask:

| Flag Bit | Hex Value | Decimal | Kerberos Algorithm | Security Assessment |
| :--- | :--- | :--- | :--- | :--- |
| Bit 0 | `0x00000001` | 1 | `DES_CBC_CRC` | Deprecated / Vulnerable to brute force |
| Bit 1 | `0x00000002` | 2 | `DES_CBC_MD5` | Deprecated / Vulnerable to collision and brute force |
| Bit 2 | `0x00000004` | 4 | `RC4_HMAC_MD5` | Cryptographically weak / Vulnerable to Kerberoasting |
| Bit 3 | `0x00000008` | 8 | `AES128_HMAC_SHA1` | Strong / Supported baseline |
| Bit 4 | `0x00000010` | 16 | `AES256_HMAC_SHA1` | Strong / Recommended baseline |
| Bit 31 | `0x80000000` | 2147483648 | `Future encryption types` | Extensibility flag for modern ciphers |

---

## Rationale
Active Directory uses the Kerberos version 5 protocol as its primary authentication mechanism. By default, Active Directory maintains backward compatibility with legacy cryptographic suites, including Data Encryption Standard (DES) and Rivest Cipher 4 (RC4-HMAC). Allowing these legacy ciphers introduces severe architectural vulnerabilities:

1. **Cryptographic Weaknesses of RC4-HMAC (RFC 4757)**:
   * **Key Derivation Flaw**: Under the RC4-HMAC Kerberos specification, the long-term secret key used to encrypt tickets is identical to the user's NTLM password hash (`MD4(UTF-16LE(password))`). No salt, no iteration count, and no cryptographic key derivation function (KDF) stretching are applied.
   * **AES vs. RC4 Cryptography**: In contrast, Kerberos AES encryption (RFC 3961 and RFC 3962) utilizes PBKDF2 with HMAC-SHA1, an account-specific salt (`DOMAINusername`), and a default work factor of 4,096 iterations. Cracking an AES Kerberos key requires exponentially more computational effort per guess than RC4.

2. **Kerberoasting & Cipher Downgrade Attacks (MITRE ATT&CK T1558.003)**:
   * Any authenticated domain user can request a Ticket Granting Service (TGS) ticket for any account with a registered Service Principal Name (SPN).
   * In a cipher downgrade attack, an attacker crafts a Kerberos `TGS-REQ` specifying only `rc4-hmac` (encryption type `23`) in the requested encryption type list. If RC4 is permitted on the Key Distribution Center (KDC), the KDC issues an RC4-encrypted service ticket—even if the target service account supports AES.
   * Because RC4 tickets use the raw NTLM hash, attackers can crack the extracted ticket offline using modern GPU rigs (Hashcat mode `13100`) at rates exceeding billions of guesses per second. By restricting KDC encryption types to AES-128 and AES-256, the KDC strictly rejects requests for weak ciphers, neutralizing Kerberoasting downgrade attacks.

3. **AS-REP Roasting Protection (MITRE ATT&CK T1558.004)**:
   * For accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH` flag enabled), any domain user can request an AS-REP authentication ticket from the KDC without supplying credentials.
   * If RC4 is enabled, the returned AS-REP ticket is encrypted using the target account's RC4/NTLM hash, allowing high-speed offline dictionary attacks (Hashcat mode `18200`). Enforcing AES ensures the KDC encrypts the AS-REP using PBKDF2-stretched AES keys.

4. **Mitigating Forged Golden & Silver Tickets (MITRE ATT&CK T1558.001 / T1558.002)**:
   * When an attacker extracts NTLM password hashes (e.g., via DCSync against `krbtgt` or a service account), they can forge arbitrary Kerberos Ticket Granting Tickets (TGTs - Golden Tickets) or Service Tickets (Silver Tickets) using RC4.
   * When RC4 is disabled domain-wide, domain members and Domain Controllers reject RC4-encrypted tickets outright. Attackers are forced to obtain the actual AES-128 or AES-256 keys, which are not exposed through simple NTLM hash dumping or relay mechanisms.

5. **PAC Signature Integrity & CVE-2022-37967 Enforcement**:
   * The Privilege Attribute Certificate (PAC) contains the user's authorization data, security identifiers (SIDs), and group memberships.
   * Security updates for CVE-2022-37967 / KB5020805 require strong HMAC-SHA1 AES algorithms for PAC signatures (`KERB_CHECKSUM_HMAC_SHA1_96_AES128` / `KERB_CHECKSUM_HMAC_SHA1_96_AES256`). Disabling RC4 guarantees consistent cryptographic security across ticket encryption, session key derivation, and PAC checksum verification.

6. **Overpass-the-Hash / Pass-the-Key Defense**:
   * In an Overpass-the-Hash attack, an attacker uses an NTLM hash as the Kerberos RC4 key to request a valid TGT. Enforcing AES-only requires authentication to use AES keys, preventing attackers from converting raw NTLM hashes into Kerberos tickets.

---

## Legacy Impact & Compatibility

* **The Kerberos Encryption Negotiation Triangle**:
  * Kerberos encryption negotiation requires consensus among four entities:
    1. **Client System**: Supported ciphers configured in the client's `SupportedEncryptionTypes` registry value.
    2. **KDC (Domain Controllers)**: Allowed ciphers configured on the Domain Controllers.
    3. **Target Account (Service or User)**: Configured via the `msDS-SupportedEncryptionTypes` attribute on the target object in Active Directory.
    4. **Account's Stored Keys in NTDS.dit**: Cryptographic keys actually generated and present in the directory database for that identity.
  * If the KDC policy forbids RC4, but the client or target account cannot support AES, authentication will fail with error `KDC_ERR_ETYPE_NOSUPP` (`0x0E` / `14` - "KDC has no support for encryption type").

* **The Password Reset Prerequisite (Missing AES Keys in NTDS.dit)**:
  * In Active Directory, AES-128 and AES-256 keys are created and populated in an account's `supplementalCredentials` attribute **only when the account's password is set or reset**.
  * Accounts created prior to Windows Server 2008, accounts migrated from legacy domains, or service accounts whose passwords have never been rotated since AES was introduced do not possess AES keys in `NTDS.dit`.
  * If RC4 is disabled on Domain Controllers, any authentication attempt for an account lacking AES keys will immediately fail with `KDC_ERR_ETYPE_NOSUPP`.
  * **Mandatory Prerequisite**: All service accounts, user accounts, and computer objects lacking AES keys must have their passwords reset before disabling RC4.

* **KRBTGT Password Rotation Requirement**:
  * The `krbtgt` account encrypts all Ticket Granting Tickets (TGTs) across the domain.
  * In domains migrated from Windows Server 2003/2008, the `krbtgt` account may still be using RC4 or lack AES keys.
  * The `krbtgt` password must be reset twice (with an interval exceeding the maximum ticket lifetime, typically 10 hours) to ensure both the current and previous `krbtgt` keys are generated with AES support. Refer to [[REQ-OPS-001] Enforce KRBTGT Password Rotation](../06-operations-maintenance/enforce-krbtgt-password-rotation.md).

* **Cross-Forest and External Trust Relationships**:
  * Inter-forest trusts, external trusts, and non-Windows realm trusts (e.g., MIT Kerberos, FreeIPA) negotiate encryption based on Trusted Domain Objects (TDOs).
  * Legacy trust relationships frequently default to RC4-only. If RC4 is disabled without enabling AES on the trust, all cross-realm authentication and cross-forest resource access will fail.
  * **Mandatory Action**: Enable AES on every trust relationship using the following command before disabling RC4:
    ```cmd
    netdom trust <DomainName> /domain:<TrustingDomain> /EnableAES:yes
    ```
    Alternatively, in **Active Directory Domains and Trusts** (`domain.msc`), open the Trust Properties and verify that **The other domain supports Kerberos AES Encryption** is checked.

* **Heterogeneous Systems & Legacy Software**:
  * **Legacy Linux/Unix Clients**: Older Samba (version 3.x) or unpatched SSSD/Winbind installations that do not have `default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96` configured in `/etc/krb5.conf` will fail.
  * **Java Runtime Environments (JRE)**: Java versions prior to 8u161 / 7u171 require the manual installation of the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files to support 256-bit AES Kerberos tickets.
  * **Embedded Appliances**: Legacy multi-function printers (MFPs) scanning to SMB shares, older Network Attached Storage (NAS) appliances, and legacy mainframe gateways may lack AES Kerberos support.

* **Pre-Remediation Auditing & Event Log Monitoring**:
  * Before applying this policy, administrators must monitor Domain Controller event logs for RC4 usage:
    * **Event ID 4768 (TGT Request)**: Check the `Ticket Encryption Type` field (`0x17` indicates RC4-HMAC; `0x12` indicates AES-256; `0x11` indicates AES-128).
    * **Event ID 4769 (TGS Service Ticket Request)**: Check `Ticket Encryption Type` and `Service Name` to identify services actively receiving RC4 tickets.
    * **Event ID 4771 (Pre-Authentication Failed)**: Monitor for Failure Code `0x0E` (`KDC_ERR_ETYPE_NOSUPP`).
    * **System Event ID 14 / 16 / 17 (Source: Kerberos-Key-Distribution-Center)**: Warnings when tickets cannot be negotiated due to missing encryption types.
  * Query Active Directory for accounts with registered SPNs that lack AES configuration:
    * `Get-ADServiceAccount -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object { -not ($_."msDS-SupportedEncryptionTypes" -band 0x18) }`
    * `Get-ADUser -Filter {ServicePrincipalNames -like "*"} -Properties msDS-SupportedEncryptionTypes | Where-Object { -not ($_."msDS-SupportedEncryptionTypes" -band 0x18) }`

* **Recommended 4-Phase Deployment Lifecycle**:
  1. **Phase 1 (Discovery)**: Audit accounts and event logs for RC4 ticket issuance. Identify legacy accounts and trusts.
  2. **Phase 2 (Remediation)**: Reset passwords on identified service accounts, rotate `krbtgt` passwords, enable AES on trust relationships, and enforce `msDS-SupportedEncryptionTypes = 24` as per [[REQ-ID-008] Enforce User and Service Account Kerberos Encryption (AES-Only)](../03-identities-services/enforce-user-aes-encryption.md).
  3. **Phase 3 (Member Server / Client Deployment)**: Apply the GPO to Member Servers, Workstations, and PAWs (`SupportedEncryptionTypes = 2147483640`).
  4. **Phase 4 (Domain Controller Enforcement)**: Apply the GPO to Domain Controllers to permanently prohibit DES and RC4 negotiation across the directory.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Network security: Configure encryption types allowed for Kerberos`
   * **Setting**: Check only the following boxes:
     * `AES128_HMAC_SHA1`
     * `AES256_HMAC_SHA1`
     * `Future encryption types`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-KerberosEncryptionTypes.ps1](implementation_scripts/Configure-KerberosEncryptionTypes.ps1)

```powershell
# Configure-KerberosEncryptionTypes.ps1
# Description: Restricts Kerberos encryption types to AES128, AES256, and Future types.

Write-Host "Applying hardening requirement: Restrict Kerberos Encryption Types..." -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# 2147483640 (0x7FFFFFF8) enables AES128, AES256, and Future encryption types
Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 2147483640 -Type DWord
Write-Host "Kerberos encryption types restricted to AES and future types." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-KerberosEncryptionStatus.ps1](audit_scripts/Get-KerberosEncryptionStatus.ps1)

```powershell
# Get-KerberosEncryptionStatus.ps1
# Description: Audits the allowed Kerberos encryption types in the registry.

Write-Host "--- Auditing Kerberos Encryption Types ---" -ForegroundColor Cyan

$regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$regVal = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

if ($regVal) {
    $encTypes = $regVal.SupportedEncryptionTypes
    
    # Check if weak algorithms are enabled (DES = 0x1, 0x2; RC4 = 0x4)
    $hasDES = ($encTypes -band 0x1) -or ($encTypes -band 0x2)
    $hasRC4 = ($encTypes -band 0x4)
    $hasAES128 = ($encTypes -band 0x8)
    $hasAES256 = ($encTypes -band 0x10)
    
    if ($hasDES -or $hasRC4) {
        Write-Host "[!] VULNERABLE: Weak Kerberos encryption algorithms are allowed (DES: $($hasDES), RC4: $($hasRC4)). SupportedEncryptionTypes raw value: $($encTypes)." -ForegroundColor Red
    } else {
        if ($hasAES128 -and $hasAES256) {
            Write-Host "[+] Kerberos encryption is secure. Restricting to AES128/AES256 (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Green
        } else {
            Write-Host "[-] Kerberos encryption configuration is custom. AES128: $($hasAES128), AES256: $($hasAES256) (SupportedEncryptionTypes: $($encTypes))." -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[!] VULNERABLE: SupportedEncryptionTypes registry value is missing. Default behavior allows insecure RC4." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Recommendation R13 (Disabling obsolete encryption algorithms) and Recommendation R14 (Kerberos encryption configuration)
* **CIS Benchmark**: CIS Microsoft Windows Server 2016 / 2019 / 2022 Benchmark - Section 2.3.7.5 (Ensure 'Network security: Configure encryption types allowed for Kerberos' is configured)
* **Microsoft Security Guidance**: [Decrypting the Selection of Supported Kerberos Encryption Types](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/259087)
* **Microsoft Support (KB5020805)**: [How to manage Kerberos protocol changes related to CVE-2022-37967](https://support.microsoft.com/en-us/topic/kb5020805-how-to-manage-kerberos-protocol-changes-related-to-cve-2022-37967-9aa255d6-d083-4a00-bb65-8b354238e8cb)
* **RFC Standards**:
  * [RFC 3961 - Encryption and Checksum Specifications for Kerberos 5](https://datatracker.ietf.org/doc/html/rfc3961)
  * [RFC 3962 - Advanced Encryption Standard (AES) Encryption for Kerberos 5](https://datatracker.ietf.org/doc/html/rfc3962)
  * [RFC 4757 - The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows](https://datatracker.ietf.org/doc/html/rfc4757)
* **MITRE ATT&CK**:
  * [Technique T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
  * [Technique T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
  * [Technique T1558.001 - Steal or Forge Kerberos Tickets: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/)
  * [Technique T1550.002 - Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/002/)
