# Module 2: Domain Controller Hardening

This directory contains security baselines for Domain Controllers running Windows Server 2016 and above in high-security, air-gapped Active Directory environments.

## Technical Hardening Controls

* **[REQ-DC-001 - Disable SMBv1](disable-smbv1.md)**
  Requirement to disable the legacy SMBv1 protocol and its associated client-side driver to prevent remote code execution and spoofing vulnerabilities.
* **[REQ-DC-002 - Disable Multicast Name Resolution](disable-multicast-name-resolution.md)**
  Requirement to disable LLMNR, NetBIOS (NBT-NS), and mDNS to prevent local name resolution spoofing and credential harvesting.
* **[REQ-DC-003 - Disable NTLMv1](disable-ntlmv1.md)**
  Requirement to restrict NTLM authentication to NTLMv2 or Kerberos to protect credentials from offline brute-force cracking.
* **[REQ-DC-004 - Enforce LDAP Server Signing](enforce-ldap-signing.md)**
  Requirement to enforce packet signing on LDAP cleartext traffic to protect directory transactions from man-in-the-middle attacks.
* **[REQ-DC-005 - Enforce LDAP Channel Binding](enforce-ldap-channel-binding.md)**
  Requirement to enforce LDAP Channel Binding Tokens (CBT) over secure LDAPS connections to prevent authentication relay attacks.
* **[REQ-DC-006 - Enable LSA Protection](enable-lsa-protection.md)**
  Requirement to configure the Local Security Authority (LSA) process to run as a Protected Process Light (PPL) to protect credential secrets from LSASS memory dumps.
* **[REQ-DC-007 - Disable Credential Guard](disable-credential-guard.md)**
  Requirement to disable Windows Defender Credential Guard on Domain Controllers in accordance with Microsoft recommendations while keeping Virtualization-Based Security (VBS) enabled.
* **[REQ-DC-008 - Disable Print Spooler Service](disable-print-spooler.md)**
  Requirement to stop and disable the Print Spooler service on Domain Controllers to prevent remote execution and coercive authentication attacks.
* **[REQ-DC-009 - Enforce SMB Message Signing](enforce-smb-signing.md)**
  Requirement to enforce SMB client and server signing to protect file transfer data and block SMB relay attacks.
* **[REQ-DC-010 - Restrict Kerberos Encryption Types](restrict-kerberos-encryption.md)**
  Requirement to configure allowed Kerberos encryption types, restricting to AES128/AES256 and disabling legacy DES and RC4 to prevent Kerberoasting.
* **[REQ-DC-011 - Restrict Remote SAM API Access](restrict-ntds-sam-api.md)**
  Requirement to restrict remote RPC access to the SAM database to local Administrators, preventing remote recon and user enumeration.
* **[REQ-DC-012 - Disable Unnecessary Services on Domain Controllers](disable-unnecessary-services.md)**
  Requirement to disable unnecessary system services (such as Xbox services and other non-essential services) on Domain Controllers to minimize the attack surface.
* **[REQ-DC-013 - Enable Kerberos Armoring](enable-kerberos-armoring.md)**
  Requirement to enable Kerberos Armoring (FAST) on Domain Controllers and client endpoints to encrypt pre-authentication exchanges and protect credentials from offline brute-force attacks.
* **[REQ-DC-014 - Restrict NTLM](restrict-ntlm.md)**
  Requirement to audit and restrict NTLMv2 and domain-wide NTLM authentication to prevent credential relaying and force the transition to Kerberos.
* **[REQ-DC-015 - Migrate SYSVOL Replication to DFSR](migrate-sysvol-replication-dfsr.md)**
  Requirement to migrate SYSVOL folder replication from legacy FRS to secure DFSR to ensure replication integrity and disable deprecated services.
* **[REQ-DC-016 - Harden adminSDHolder Permissions](harden-adminsdholder-permissions.md)**
  Requirement to secure the adminSDHolder object's Access Control List to prevent privilege escalation backdoors on protected accounts.
* **[REQ-DC-017 - Harden Microsoft DNS AD Container Permissions](harden-dns-container-permissions.md)**
  Requirement to secure CN=MicrosoftDNS,CN=System container permissions and block DNS service DLL hijacking (ServerLevelPluginDll).
* **[REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](harden-dc-virtualization-hosts.md)**
  Requirement to treat virtualization hypervisors hosting Domain Controllers as Tier 0 systems, separating host hardware and enforcing VM encryption.
* **[REQ-DC-019 - Enforce RDP Restricted Admin Mode](enforce-rdp-restricted-admin.md)**
  Requirement to configure and require RDP Restricted Admin Mode on administrative clients and servers to protect credentials in host memory.
* **[REQ-DC-020 - Windows Defender Antivirus Domain Controller Baseline and Exploit Guard](defender-antivirus.md)**
  Requirement to configure and harden Windows Defender Antivirus on Domain Controllers, enabling real-time scanning, preventing local exclusion modifications, enforcing server-compatible ASR rules (including LSASS protection), activating Tamper Protection, and sandboxing execution.
* **[REQ-DC-021 - Configure AppLocker Policies on Domain Controllers](configure-applocker-policies.md)**
  Requirement to configure strict AppLocker rules on Domain Controllers to prevent administrative users from executing unapproved binaries, scripts, installers, or web browsers on Tier 0 systems.
* **[REQ-DC-022 - Enable WDAC Driver Blocklist](enable-wdac-driver-blocklist.md)**
  Requirement to configure the Windows Defender Application Control (WDAC) driver blocklist to protect kernel memory from Bring Your Own Vulnerable Driver (BYOVD) attacks.
* **[REQ-DC-023 - Configure User Rights Assignments for Domain Controllers](configure-user-rights-assignments.md)**
  Requirement to restrict local user rights assignments on Domain Controllers to prevent default operator groups (Print Operators, Server Operators, Backup Operators) from logging on locally, backing up/restoring files, or shutting down Domain Controllers.
* **[REQ-DC-024 - Configure dSHeuristics](configure-dsheuristics.md)**
  Requirement to audit and configure the dSHeuristics forest-wide attribute to reach maximum Level 5 security, blocking anonymous LDAP and NSPI operations, securing adminSDHolder, and enforcing KB5008383 owner implicit rights protections.
* **[REQ-DC-025 - Configure Security Options for Domain Controllers](configure-security-options.md)**
  Requirement to configure baseline administrative template Security Options, disabling anonymous access to SAM/shares and enforcing credential policies.
* **[REQ-DC-026 - Configure TCP/IP and Network Parameter Hardening for Domain Controllers](harden-network-parameters.md)**
  Requirement to configure hardened network configurations, TCP/IP MSS parameters, disabling LLTDIO/RSPNDR drivers, Peer-to-Peer, and Windows Connect Now.
* **[REQ-DC-027 - Configure Telemetry, Diagnostics and Privacy Options for Domain Controllers](configure-telemetry-privacy.md)**
  Requirement to restrict telemetry collection, online diagnostics, advertising IDs, diagnostic tools, and cloud content integration.
* **[REQ-DC-028 - Configure Untrusted Font Blocking for Domain Controllers](configure-untrusted-font-blocking.md)**
  Requirement to configure the Untrusted Font Blocking mitigation on Domain Controllers to prevent kernel font parser exploits.




