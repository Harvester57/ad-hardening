# Configure Account and Password Policies

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies`
  * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * `Computer Configuration\Administrative Templates\System\PIN Complexity`
  * `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
  * `Computer Configuration\Administrative Templates\Windows Components\Windows Hello for Business`
  * `Computer Configuration\Preferences\Windows Settings\Registry`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above

---

## Rationale

Securing authentication parameters, credential caching thresholds, account lockout observation windows, and interactive logon behaviors establishes a fundamental defense against password spraying, offline cracking, and unauthorized lateral movement across the enterprise fleet.

While individual workstations may operate in standard user environments, a compromise on any single endpoint can serve as a beachhead for domain reconnaissance and credential harvesting. Enforcing consistent, hardened account policies across all client systems neutralizes classic post-exploitation vectors:

### Architectural Threat Vectors & Security Objectives
1. **Elevating Password Entropy**: A 14-character minimum password length expands the keyspace to over `4.6 x 10^27` combinations, defeating offline dictionary attacks while aligning with NIST SP 800-63B guidelines (eliminating forced periodic expirations).
2. **Defeating Automated Brute Force**: Enforcing a 10-attempt lockout threshold with a 15-minute lockout window (and extending lockout enforcement to the built-in Administrator) stops automated attack scripts.
3. **Fortifying Credential Caching**: Disabling cached logons (`CachedLogonsCount = 0`) on fixed workstations and setting `NL$IterationCount = 1954` (~2M rounds) on roaming field laptops prevents offline GPU-accelerated cracking of DCC2 hashes.
4. **Purging Weak Authentication**: Enforcing NTLMv2 with 128-bit session security, disabling WDigest in-memory plaintext caching, and blocking null sessions protects authentication traffic from interception and relay attacks.
5. **Physical & Interactive Security**: Mandating the hardware Secure Attention Sequence (`CTRL+ALT+DEL`), hiding the last signed-in username, and locking on smart card removal eliminates casual physical snooping and rogue logon prompts.
6. **Protecting Secure Channel Communication**: Enforcing cryptographic sealing, signing, and 30-day machine password rotation ensures the integrity of domain communication and thwarts ZeroLogon-style vulnerabilities.

---

## Legacy Impact & Compatibility

* **Password Passphrase Adoption**: Users with passwords shorter than 14 characters must update their credentials to meet the length requirement. User education should focus on memorable passphrases.
* **Lockout Behavior**: Users who mistype their password 10 times will experience a 15-minute temporary lockout, after which the account will automatically unlock without IT intervention.
* **Roaming Laptops vs Fixed Desktops**: Desktops enforce `CachedLogonsCount = 0` requiring live domain connectivity. Roaming laptops without pre-logon VPN must be placed in a dedicated OU allowing a limited cache (e.g., 2 logons) fortified with `NL$IterationCount = 1954` and BitLocker TPM+PIN.
* **Modernized Web Applications**: Intranet applications requiring HTTP Digest authentication must be updated to modern Kerberos, SAML, or OAuth 2.0 federation.

---

## Account Policy Hardening Requirements

The following individual account and authentication policies must be enforced:

1. **[REQ-END-163 - Account Policy: Password Policy for Endpoints](account-policy/configure-end-account-password-policy.md)**
2. **[REQ-END-164 - Account Policy: Account Lockout Policy for Endpoints](account-policy/configure-end-account-lockout-policy.md)**
3. **[REQ-END-165 - Account Policy: Kerberos Policy for Endpoints](account-policy/configure-end-account-kerberos-policy.md)**
4. **[REQ-END-166 - Account Policy: Smart Card Removal Behavior for Endpoints](account-policy/configure-end-account-smart-card-removal.md)**
5. **[REQ-END-167 - Account Policy: Cached Logons and PBKDF2 Iteration Count for Endpoints](account-policy/configure-end-account-cached-logons.md)**
6. **[REQ-END-168 - Account Policy: Local Accounts and Blank Password Restrictions for Endpoints](account-policy/configure-end-account-local-blank-passwords.md)**
7. **[REQ-END-169 - Account Policy: NTLM and LAN Manager Authentication Security for Endpoints](account-policy/configure-end-account-ntlm-security.md)**
8. **[REQ-END-170 - Account Policy: Disable WDigest Credential Caching for Endpoints](account-policy/configure-end-account-wdigest-credentials.md)**
9. **[REQ-END-171 - Account Policy: Windows Hello for Business and PIN Complexity for Endpoints](account-policy/configure-end-account-hello-pin.md)**
10. **[REQ-END-172 - Account Policy: Consumer Microsoft Account Restrictions for Endpoints](account-policy/configure-end-account-block-msa.md)**
11. **[REQ-END-173 - Account Policy: Domain Member Secure Channel Security for Endpoints](account-policy/configure-end-account-secure-channel.md)**
12. **[REQ-END-174 - Account Policy: SMB Client and Server Security Options for Endpoints](account-policy/configure-end-account-smb-security.md)**
13. **[REQ-END-175 - Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints](account-policy/configure-end-account-anonymous-restrictions.md)**
14. **[REQ-END-176 - Account Policy: Interactive Logon Security Options for Endpoints](account-policy/configure-end-account-interactive-logon.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Enterprise Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 1.3 (Kerberos Policy), Section 2.3 (Security Options), Section 18 (Administrative Templates)
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 1.1, Section 1.2, Section 1.3, Section 2.3, Section 18
* **DoD Windows 11 Computer STIG**: Account policies, PIN complexity, Windows Hello for Business, and Netlogon secure channel parameters
* **ANSSI Active Directory Hardening Guide**: Recommendations on password entropy, lockout management, and domain member secure channels
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Account Policies & Local Policies Security Options
