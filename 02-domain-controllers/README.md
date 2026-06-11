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
* **[Enable Kerberos Armoring](enable-kerberos-armoring.md)**
  Requirement to enable Kerberos Armoring (FAST) on Domain Controllers and client endpoints to encrypt pre-authentication exchanges and protect credentials from offline brute-force attacks.
* **[Restrict NTLM](restrict-ntlm.md)**
  Requirement to audit and restrict NTLMv2 and domain-wide NTLM authentication to prevent credential relaying and force the transition to Kerberos.
* **[Migrate SYSVOL Replication to DFSR](migrate-sysvol-replication-dfsr.md)**
  Requirement to migrate SYSVOL folder replication from legacy FRS to secure DFSR to ensure replication integrity and disable deprecated services.
* **[Harden adminSDHolder Permissions](harden-adminsdholder-permissions.md)**
  Requirement to secure the adminSDHolder object's Access Control List to prevent privilege escalation backdoors on protected accounts.
* **[Harden Microsoft DNS AD Container Permissions](harden-dns-container-permissions.md)**
  Requirement to secure CN=MicrosoftDNS,CN=System container permissions and block DNS service DLL hijacking (ServerLevelPluginDll).
* **[Harden Virtualization Hosts for Domain Controllers](harden-dc-virtualization-hosts.md)**
  Requirement to treat virtualization hypervisors hosting Domain Controllers as Tier 0 systems, separating host hardware and enforcing VM encryption.
* **[Enforce RDP Restricted Admin Mode](enforce-rdp-restricted-admin.md)**
  Requirement to configure and require RDP Restricted Admin Mode on administrative clients and servers to protect credentials in host memory.
* **[Windows Defender Antivirus DC Baseline and Exploit Guard](defender-antivirus.md)**
  Requirement to configure and harden Windows Defender Antivirus on Domain Controllers, enabling real-time scanning, preventing local exclusion modifications, enforcing server-compatible ASR rules (including LSASS protection), activating Tamper Protection, and sandboxing execution.
* **[Configure AppLocker Policies on Domain Controllers](configure-applocker-policies.md)**
  Requirement to configure strict AppLocker rules on Domain Controllers to prevent administrative users from executing unapproved binaries, scripts, installers, or web browsers on Tier 0 systems.


