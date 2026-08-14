# Configure Account and Password Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

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
Privileged Access Workstations (PAWs) represent the highest security boundary on the endpoint layer, serving as isolated systems dedicated solely to Tier 0 directory administration. If a PAW is compromised, the entire AD forest is compromised. Therefore, authentication parameters, local password policies, account lockouts, secure channel settings, and interactive logon behaviors must be hardened to their absolute maximum threshold.

This submodule contains individual requirement controls for each specific account policy, lockout setting, authentication restriction, and interactive logon control on PAWs.

---

## Legacy Impact & Compatibility
* **Account Lockouts**: Legitimate administrators who forget their passwords may lock themselves out. Standard procedures must exist for administrative reset of locked accounts by another Tier 0 administrator.
* **Smart Card Removal**: Administrators must be trained to carry their smart cards with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.
* **Logon Caching (CachedLogonsCount = 0)**: PAWs must have active, real-time connectivity to a Domain Controller to allow users to log on. Off-domain logons without live DC contact will fail.
* **No Password Expiration**: Removing periodic password changes minimizes helpdesk tickets and stops administrators from choosing predictable increments. Credential revocation and rotation protocols must remain active for suspected leaks.

---

## Account Policy Hardening Requirements for PAWs

The following individual account and authentication policies must be enforced on PAWs:

1. **[REQ-PAW-152 - Account Policy: Password Policy for PAWs](account-policy/configure-paw-account-password-policy.md)**
2. **[REQ-PAW-153 - Account Policy: Account Lockout Policy for PAWs](account-policy/configure-paw-account-lockout-policy.md)**
3. **[REQ-PAW-154 - Account Policy: Kerberos Policy for PAWs](account-policy/configure-paw-account-kerberos-policy.md)**
4. **[REQ-PAW-155 - Account Policy: Smart Card Removal Behavior for PAWs](account-policy/configure-paw-account-smart-card-removal.md)**
5. **[REQ-PAW-156 - Account Policy: Cached Logons and PBKDF2 Iteration Count for PAWs](account-policy/configure-paw-account-cached-logons.md)**
6. **[REQ-PAW-157 - Account Policy: Local Accounts and Blank Password Restrictions for PAWs](account-policy/configure-paw-account-local-blank-passwords.md)**
7. **[REQ-PAW-158 - Account Policy: NTLM and LAN Manager Authentication Security for PAWs](account-policy/configure-paw-account-ntlm-security.md)**
8. **[REQ-PAW-159 - Account Policy: Disable WDigest Credential Caching for PAWs](account-policy/configure-paw-account-wdigest-credentials.md)**
9. **[REQ-PAW-160 - Account Policy: Windows Hello for Business and PIN Complexity for PAWs](account-policy/configure-paw-account-hello-pin.md)**
10. **[REQ-PAW-161 - Account Policy: Consumer Microsoft Account Restrictions for PAWs](account-policy/configure-paw-account-block-msa.md)**
11. **[REQ-PAW-162 - Account Policy: Domain Member Secure Channel Security for PAWs](account-policy/configure-paw-account-secure-channel.md)**
12. **[REQ-PAW-163 - Account Policy: SMB Client and Server Security Options for PAWs](account-policy/configure-paw-account-smb-security.md)**
13. **[REQ-PAW-164 - Account Policy: Anonymous Access and Enumeration Restrictions for PAWs](account-policy/configure-paw-account-anonymous-restrictions.md)**
14. **[REQ-PAW-165 - Account Policy: Interactive Logon Security Options for PAWs](account-policy/configure-paw-account-interactive-logon.md)**

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 2.3 (Security Options), Section 18 (Administrative Templates)
* **ANSSI AD Hardening Guide**: Recommendations on password complexity, reversible encryption blocks, lockout management, and domain member secure channels
* **DoD Windows 11 Computer STIG v2r6**: Account policies, PIN complexity, Windows Hello for Business, and Netlogon secure channel parameters
