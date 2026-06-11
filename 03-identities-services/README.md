# Module 3: Identities & Services Hardening

This directory contains security requirements and policies designed to protect administrative identities, user credentials, and critical network service accounts in the Active Directory domain.

## Technical Hardening Controls

1. **[Enforce Fine-Grained Password Policies](enforce-fgpp.md)**
   Enforces Password Settings Objects (PSOs) with strong password length and lockout settings for administrative groups.

2. **[Enable Local Administrator Password Solution (LAPS)](enable-laps.md)**
   Implements Windows LAPS or Classic LAPS to rotate local administrator passwords periodically.

3. **[Implement Group Managed Service Accounts (gMSA)](harden-service-accounts.md)**
   Replaces static passwords with auto-managed complex service account credentials.

4. **[Restrict Kerberos Delegation](restrict-kerberos-delegation.md)**
   Bans unconstrained delegation and mandates constrained/resource-based constrained delegation.

5. **[Configure and Populate Protected Users Group](configure-protected-users-group.md)**
   Enforces strict caching and authentication restrictions on high-privilege identities to prevent credential theft.

6. **[Rename and Disable Default Administrator and Guest Accounts](harden-default-accounts.md)**
   Mitigates automated scanning and brute-force attempts on built-in OS accounts.

7. **[Restrict Interactive Logons for Service Accounts](restrict-service-account-logons.md)**
   Blocks interactive local and remote desktop logons for service accounts via User Rights Assignment GPOs.

8. **[Enforce User and Service Account Kerberos Encryption (AES-Only)](enforce-user-aes-encryption.md)**
   Sets the msDS-SupportedEncryptionTypes attribute to AES-only to mitigate Kerberoasting and session hijacking.
