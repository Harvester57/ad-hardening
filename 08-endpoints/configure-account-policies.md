# Configure Account and Password Policies

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies`
  * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * `Computer Configuration\Administrative Templates\System\PIN Complexity`
  * `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
  * `Computer Configuration\Administrative Templates\Windows Components\Windows Hello for Business`

---

## Rationale
Securing authentication parameters, credential caching thresholds, account lockout windows, and interactive logon behaviors establishes a fundamental defense against password spraying, offline cracking, and unauthorized lateral movement.

This submodule contains individual requirement controls for each specific account policy, lockout setting, authentication restriction, and interactive logon control across enterprise client workstations and member servers.

---

## Legacy Impact & Compatibility
* **Account Lockouts**: Legitimate users who forget their passwords may lock themselves out. Standard procedures must exist for administrative reset of locked accounts.
* **Smart Card Removal**: Users must be trained to carry their smart cards with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.
* **Minimum Password Length (14 characters)**: Users with short passwords will be forced to choose a longer password (at least 14 characters) during their next password change.
* **No Password Expiration (MaxPasswordAge = 0)**: Users will no longer be prompted to periodically change their passwords, reducing helpdesk calls related to expired password lockouts and discouraging the use of weak incremental password schemes.
* **Logon Caching (CachedLogonsCount = 0)**: Workstations must have active, real-time connectivity to a Domain Controller to allow users to log on.

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
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 1.3 (Kerberos Policy), Section 2.3 (Security Options), Section 18 (Administrative Templates)
* **ANSSI AD Hardening Guide**: Recommendations on password complexity, reversible encryption blocks, lockout management, and domain member secure channels
* **DoD Windows 11 Computer STIG v2r6**: Account policies, PIN complexity, Windows Hello for Business, and Netlogon secure channel parameters
