# Module 3: Identities & Services Hardening

This directory contains security requirements and policies designed to protect administrative identities, user credentials, and critical network service accounts in the Active Directory domain.

## Technical Hardening Controls

1. **[REQ-ID-001 - Enforce Fine-Grained Password Policies](enforce-fgpp.md)**
   Enforces Password Settings Objects (PSOs) with strong password length and lockout settings for administrative groups.

2. **[REQ-ID-002 - Enable Local Administrator Password Solution (LAPS)](enable-laps.md)**
   Implements Windows LAPS or Classic LAPS to rotate local administrator passwords periodically.

3. **[REQ-ID-003 - Implement Group Managed Service Accounts (gMSA)](harden-service-accounts.md)**
   Replaces static passwords with auto-managed complex service account credentials.

4. **[REQ-ID-004 - Restrict Kerberos Delegation](restrict-kerberos-delegation.md)**
   Bans unconstrained delegation and mandates constrained/resource-based constrained delegation.

5. **[REQ-ID-005 - Configure and Populate Protected Users Group](configure-protected-users-group.md)**
   Enforces strict caching and authentication restrictions on high-privilege identities to prevent credential theft.

6. **[REQ-ID-006 - Rename and Disable Default Administrator and Guest Accounts](harden-default-accounts.md)**
   Mitigates automated scanning and brute-force attempts on built-in OS accounts.

7. **[REQ-ID-007 - Restrict Interactive Logons for Service Accounts](restrict-service-account-logons.md)**
   Blocks interactive local and remote desktop logons for service accounts via User Rights Assignment GPOs.

8. **[REQ-ID-008 - Enforce User and Service Account Kerberos Encryption (AES-Only)](enforce-user-aes-encryption.md)**
   Sets the msDS-SupportedEncryptionTypes attribute to AES-only to mitigate Kerberoasting and session hijacking.

9. **[REQ-ID-009 - Enforce Kerberos Pre-Authentication](enforce-kerberos-preauthentication.md)**
   Mandates Kerberos pre-authentication on all active user accounts to mitigate AS-REP Roasting attacks.

10. **[REQ-ID-010 - Restrict Schema Administrators Group Membership](restrict-schema-admins.md)**
    Automates Schema Admins membership audit and locking using Restricted Groups GPO to minimize the attack surface.

11. **[REQ-ID-011 - Enforce Accidental Deletion Protection on Organizational Units](prevent-accidental-deletion-ous.md)**
    Safeguards OUs from deletion errors or malicious administrative actions via the `ProtectedFromAccidentalDeletion` attribute.

12. **[REQ-ID-012 - Configure Active Directory Authentication Silos and Policies](configure-authentication-silos.md)**
    Enforces logical boundaries restricting where Tier 0 administrator and host accounts can authenticate, preventing credential theft.

13. **[REQ-ID-013 - Clean Up adminCount Attribute Orphans](cleanup-admincount-orphans.md)**
    Identifies and remediates orphan accounts with disabled security descriptor inheritance, resetting adminCount to 0 and re-enabling inheritance.

14. **[REQ-ID-014 - Renew KDS Root Keys and gMSA Secrets](renew-kds-keys-gmsa-secrets.md)**
    Enforces KDS root key rotation and triggers password regeneration for Group Managed Service Accounts to mitigate exfiltration backdoors.

15. **[REQ-ID-015 - Harden Active Directory Certificate Services (ADCS) and PKI](harden-adcs-pki.md)**
    Hardens ADCS templates to block ESC1 SAN enrollment bypasses, mandates manager approval, and secures CA Web Enrollment endpoints.

16. **[REQ-ID-016 - Configure Logon Screen and Credentials Delegation](configure-credential-delegation.md)**
    Restricts logon screen user enumeration, and hardens CredSSP/credentials delegation.

17. **[REQ-ID-017 - Disable Machine Account Quota](disable-machine-account-quota.md)**
    Restricts the ms-DS-MachineAccountQuota attribute to 0 and limits the SeMachineAccountPrivilege user right to prevent unauthorized computer object creation by standard domain users.

18. **[REQ-ID-018 - Restrict Pre-Windows 2000 Compatible Access Group](restrict-pre-windows-2000-compatible-access-group.md)**
    Limits the memberships of the legacy "Pre-Windows 2000 Compatible Access" group and restricts anonymous query options to prevent directory enumeration.
