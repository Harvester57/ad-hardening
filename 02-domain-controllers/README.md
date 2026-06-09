# Module 2: Domain Controller Hardening

This directory contains security baselines for Domain Controllers running Windows Server 2016 and above in high-security, air-gapped Active Directory environments.

## Technical Hardening Controls

* **[Disable SMBv1](disable-smbv1.md)**
  Requirement to disable the legacy SMBv1 protocol and its associated client-side driver to prevent remote code execution and spoofing vulnerabilities.
* **[Disable Multicast Name Resolution](disable-multicast-name-resolution.md)**
  Requirement to disable LLMNR, NetBIOS (NBT-NS), and mDNS to prevent local name resolution spoofing and credential harvesting.
* **[Disable NTLMv1](disable-ntlmv1.md)**
  Requirement to restrict NTLM authentication to NTLMv2 or Kerberos to protect credentials from offline brute-force cracking.
* **[Enforce LDAP Server Signing](enforce-ldap-signing.md)**
  Requirement to enforce packet signing on LDAP cleartext traffic to protect directory transactions from man-in-the-middle attacks.
* **[Enforce LDAP Channel Binding](enforce-ldap-channel-binding.md)**
  Requirement to enforce LDAP Channel Binding Tokens (CBT) over secure LDAPS connections to prevent authentication relay attacks.
* **[Enable LSA Protection](enable-lsa-protection.md)**
  Requirement to configure the Local Security Authority (LSA) process to run as a Protected Process Light (PPL) to protect credential secrets from LSASS memory dumps.
* **[Enable Credential Guard](enable-credential-guard.md)**
  Requirement to enable Windows Defender Credential Guard using Virtualization-Based Security (VBS) to hardware-isolate credential secrets.
* **[Disable Print Spooler Service](disable-print-spooler.md)**
  Requirement to stop and disable the Print Spooler service on Domain Controllers to prevent remote execution and coercive authentication attacks.
* **[Enforce SMB Message Signing](enforce-smb-signing.md)**
  Requirement to enforce SMB client and server signing to protect file transfer data and block SMB relay attacks.
* **[Restrict Kerberos Encryption Types](restrict-kerberos-encryption.md)**
  Requirement to configure allowed Kerberos encryption types, restricting to AES128/AES256 and disabling legacy DES and RC4 to prevent Kerberoasting.
* **[Restrict Remote SAM API Access](restrict-ntds-sam-api.md)**
  Requirement to restrict remote RPC access to the SAM database to local Administrators, preventing remote recon and user enumeration.
* **[Disable Unnecessary Services](disable-unnecessary-services.md)**
  Requirement to disable unnecessary system services (such as Xbox services and other non-essential services) on Domain Controllers to minimize the attack surface.
