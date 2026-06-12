# Active Directory Hardening Guidebook

Welcome to the **Active Directory Hardening Guidebook**. This repository contains a structured, production-grade set of hardening requirements and guidelines specifically designed for securing **modern Active Directory (AD) environments** in **air-gapped (offline)** settings. 

The guide is tailored for:
* **Domain Controllers**: Windows Server 2016 (and above).
* **Clients**: Windows 10 (and above) enterprise workstations.
* **Environment**: High-security, isolated (air-gapped) environments with no direct internet connection, no Azure/Entra ID integrations, and no external cloud services.

All security recommendations contained herein are aligned with the following cybersecurity standards:
* **ANSSI** (French National Agency for the Security of Information Systems) - *Hardening an Active Directory Directory Service*
* **CIS Benchmarks** (Center for Internet Security) - *Windows Server 2016 & Windows 10*
* **Microsoft Security Baselines**

---

### Table of Contents

The guidebook is organized into eight functional modules:

1. **[Module 1: Architecture & Administrative Tiering](01-architecture/README.md)**
   * Entry point index and technical treatise on Active Directory tiering and administrative boundaries.
   * Hardening controls:
     * [Restrict Tier Logons](01-architecture/restrict-tier-logons.md)
     * [Restrict Administrative Management Protocols](01-architecture/restrict-mgmt-protocols.md)
     * [Audit Privileged Groups](01-architecture/audit-privileged-groups.md)
     * [Keep Functional Levels Up-To-Date](01-architecture/keep-functional-levels-up-to-date.md)
     * [Default Domain and Domain Controllers Policies Management](01-architecture/default-policies-recommendations.md)
     * [Harden Active Directory Domain Trusts](01-architecture/harden-domain-trusts.md)
2. **[Module 2: Domain Controller Hardening](02-domain-controllers/README.md)**
   * Operating system-level DC security configuration.
   * Hardening controls:
     * [Disable SMBv1](02-domain-controllers/disable-smbv1.md)
     * [Disable Multicast Name Resolution](02-domain-controllers/disable-multicast-name-resolution.md)
     * [Disable NTLMv1](02-domain-controllers/disable-ntlmv1.md)
     * [Enforce LDAP Server Signing](02-domain-controllers/enforce-ldap-signing.md)
     * [Enforce LDAP Channel Binding](02-domain-controllers/enforce-ldap-channel-binding.md)
     * [Enable LSA Protection](02-domain-controllers/enable-lsa-protection.md)
     * [Enable Credential Guard](02-domain-controllers/enable-credential-guard.md)
     * [Disable Print Spooler Service](02-domain-controllers/disable-print-spooler.md)
     * [Enforce SMB Message Signing](02-domain-controllers/enforce-smb-signing.md)
     * [Restrict Kerberos Encryption Types](02-domain-controllers/restrict-kerberos-encryption.md)
     * [Restrict Remote SAM API Access](02-domain-controllers/restrict-ntds-sam-api.md)
     * [Disable Unnecessary Services](02-domain-controllers/disable-unnecessary-services.md)
     * [Enable Kerberos Armoring](02-domain-controllers/enable-kerberos-armoring.md)
     * [Restrict NTLM](02-domain-controllers/restrict-ntlm.md)
     * [Migrate SYSVOL Replication to DFSR](02-domain-controllers/migrate-sysvol-replication-dfsr.md)
     * [Harden adminSDHolder Permissions](02-domain-controllers/harden-adminsdholder-permissions.md)
     * [Harden Microsoft DNS AD Container Permissions](02-domain-controllers/harden-dns-container-permissions.md)
     * [Harden Virtualization Hosts for Domain Controllers](02-domain-controllers/harden-dc-virtualization-hosts.md)
     * [Enforce RDP Restricted Admin Mode](02-domain-controllers/enforce-rdp-restricted-admin.md)
     * [Windows Defender Antivirus DC Baseline and Exploit Guard](02-domain-controllers/defender-antivirus.md)
     * [Configure AppLocker Policies on Domain Controllers](02-domain-controllers/configure-applocker-policies.md)
3. **[Module 3: Identities & Services Hardening](03-identities-services/README.md)**
   * Administrative identity protection, credential hygiene, and service account hardening.
   * Hardening controls:
     * [Enforce Fine-Grained Password Policies](03-identities-services/enforce-fgpp.md)
     * [Enable Local Administrator Password Solution (LAPS)](03-identities-services/enable-laps.md)
     * [Implement Group Managed Service Accounts (gMSA)](03-identities-services/harden-service-accounts.md)
     * [Restrict Kerberos Delegation](03-identities-services/restrict-kerberos-delegation.md)
     * [Configure and Populate Protected Users Group](03-identities-services/configure-protected-users-group.md)
     * [Rename and Disable Default Administrator and Guest Accounts](03-identities-services/harden-default-accounts.md)
     * [Restrict Interactive Logons for Service Accounts](03-identities-services/restrict-service-account-logons.md)
     * [Enforce User and Service Account Kerberos Encryption (AES-Only)](03-identities-services/enforce-user-aes-encryption.md)
     * [Enforce Kerberos Pre-Authentication](03-identities-services/enforce-kerberos-preauthentication.md)
     * [Restrict Schema Administrators Group Membership](03-identities-services/restrict-schema-admins.md)
     * [Enforce Accidental Deletion Protection on Organizational Units](03-identities-services/prevent-accidental-deletion-ous.md)
     * [Configure Active Directory Authentication Silos](03-identities-services/configure-authentication-silos.md)
     * [Clean Up adminCount Attribute Orphans](03-identities-services/cleanup-admincount-orphans.md)
     * [Renew KDS Root Keys and gMSA Secrets](03-identities-services/renew-kds-keys-gmsa-secrets.md)
     * [Harden Active Directory Certificate Services (ADCS)](03-identities-services/harden-adcs-pki.md)
     * [Configure Point and Print Restrictions](03-identities-services/configure-point-and-print.md)
     * [Disable Machine Account Quota](03-identities-services/disable-machine-account-quota.md)
     * [Restrict Pre-Windows 2000 Compatible Access Group](03-identities-services/restrict-pre-windows-2000-compatible-access-group.md)
4. **[Module 4: Network Configuration & Firewalling](04-network-firewall/README.md)**
   * Active Directory network boundaries, port configurations, and encryption/authentication configurations.
   * Hardening controls:
     * [Configure Active Directory Port Matrix](04-network-firewall/configure-ad-port-matrix.md)
     * [Restrict RPC Dynamic Ports](04-network-firewall/restrict-rpc-dynamic-ports.md)
     * [Configure Workstation and Server Isolation](04-network-firewall/configure-workstation-isolation.md)
     * [Configure IPsec Domain Isolation](04-network-firewall/configure-ipsec-domain-isolation.md)
     * [Harden IPsec Cryptographic Configurations](04-network-firewall/harden-ipsec-cryptography.md)
     * [Harden TLS Protocols, Cipher Suites, and Elliptic Curves](04-network-firewall/harden-tls-configuration.md)
     * [Enforce SMBv3 Security and Digitally Sign/Encrypt Communications](04-network-firewall/enforce-smbv3-security.md)
     * [Configure Firewall Logging and Operational Settings](04-network-firewall/configure-firewall-logging.md)
     * [Configure Hardened UNC Paths](04-network-firewall/configure-hardened-unc-paths.md)
     * [Harden WinRM Service and Restrict RPC Clients](04-network-firewall/harden-winrm-service.md)
5. **[Module 5: Logging, Monitoring & SIEM](05-logging-monitoring/README.md)**
   * Entry point index for security log auditing, host monitoring, and centralized SIEM ingestion.
   * Hardening controls:
     * [Configure Advanced Security Audit Policies](05-logging-monitoring/configure-advanced-audit-policies.md)
     * [Configure PowerShell and Command-Line Auditing](05-logging-monitoring/configure-powershell-and-command-line-auditing.md)
     * [Deploy and Harden Microsoft Sysmon](05-logging-monitoring/deploy-and-harden-sysmon.md)
     * [Configure Secure SIEM Log Shipping](05-logging-monitoring/configure-siem-log-shipping.md)
6. **[Module 6: Secure Operations & Maintenance](06-operations-maintenance/README.md)**
   * AD System State backup, restore, and offline immutable storage.
   * Hardening controls:
     * [Secure Operations and Maintenance Baseline](06-operations-maintenance/ops-and-maintenance.md)
     * [Enforce KRBTGT Password Rotation](06-operations-maintenance/enforce-krbtgt-password-rotation.md)
     * [Enable and Configure Active Directory Recycle Bin](06-operations-maintenance/enable-recycle-bin.md)
     * [Establish and Maintain Group Policy ADMX Central Store](06-operations-maintenance/maintain-gpo-templates.md)
     * [Implement Third-Party and Custom GPO Templates for COTS Hardening](06-operations-maintenance/use-third-party-templates.md)
     * [Configure Dedicated WSUS for Tier 0](06-operations-maintenance/configure-dedicated-tier0-wsus.md)
7. **[Module 7: Privileged Access Workstations (PAWs) Hardening](07-paws/README.md)**
   * Physical and operating system isolation rules for administration devices.
   * Hardening controls:
     * [Configure AppLocker Policies for PAWs](07-paws/configure-applocker-policies.md)
     * [Enable LSA Protection for PAWs](07-paws/enable-lsa-protection.md)
     * [Restrict Local Administrators Group for PAWs](07-paws/restrict-local-administrators.md)
     * [Enable BitLocker for PAWs](07-paws/enable-bitlocker.md)
     * [UEFI Firmware Security Hardening](07-paws/configure-uefi-security.md)
     * [Hardware Virtualization and DMA Protection](07-paws/enable-hardware-virtualization-and-dma-protection.md)
     * [Disable Windows Platform Binary Table (WPBT)](07-paws/disable-wpbt.md)
     * [Windows Defender Antivirus PAW Baseline and Exploit Guard](07-paws/defender-antivirus.md)
     * [Configure User Rights Assignments for PAWs](07-paws/configure-user-rights-assignments.md)
     * [Enable VBS and Credential Guard for PAWs](07-paws/enable-vbs-credential-guard.md)
     * [Harden DMA and Physical Security for PAWs](07-paws/harden-dma-and-physical-security.md)
8. **[Module 8: Endpoint Hardening](08-endpoints/README.md)**
   * Entry point index for Tier 2 workstation security.
   * Hardening controls:
     * [Harden Network and Name Resolution](08-endpoints/harden-network-and-name-resolution.md)
     * [Configure UAC Policies](08-endpoints/configure-uac-policies.md)
     * [Disable AutoPlay and AutoRun](08-endpoints/disable-autoplay-autorun.md)
     * [Block Removable Storage](08-endpoints/block-removable-storage.md)
     * [Restrict Remote Desktop (RDP) Access](08-endpoints/restrict-rdp-access.md)
     * [Restrict Local Administrators Group](08-endpoints/restrict-local-admins.md)
     * [Windows Defender Antivirus Offline Baseline](08-endpoints/defender-antivirus.md)
     * [WSUS Client Configuration](08-endpoints/wsus-client-config.md)
     * [Enable Secure Boot](08-endpoints/enable-secure-boot.md)
     * [Enable VBS and Credential Guard](08-endpoints/enable-vbs-credential-guard.md)
     * [Configure Windows Defender Application Control](08-endpoints/configure-wdac.md)
     * [Enable BitLocker and Network Unlock](08-endpoints/enable-bitlocker.md)
     * [UEFI Firmware Security Hardening](08-endpoints/configure-uefi-security.md)
     * [Hardware Virtualization and DMA Protection](08-endpoints/enable-hardware-virtualization-and-dma-protection.md)
     * [Disable Windows Platform Binary Table (WPBT)](08-endpoints/disable-wpbt.md)
     * [Configure User Rights Assignments](08-endpoints/configure-user-rights-assignments.md)
     * [Harden DMA and Physical Security](08-endpoints/harden-dma-and-physical-security.md)
     * [Configure Account Policies](08-endpoints/configure-account-policies.md)
     * [Configure User Profile Restrictions](08-endpoints/configure-user-profile-restrictions.md)
     * [Block Outbound Traffic for Known LOLBins](08-endpoints/block-lolbins-outbound-traffic.md)

---

## Compliance Mapping Matrix

Below is a cross-reference matrix mapping each guidebook module to specific guidelines from **ANSSI**, **CIS**, and **Microsoft Security Baselines**:

| Module | ANSSI AD Guide Recommendation | CIS Windows Server/10 Benchmark | Microsoft Security Baseline Focus |
| :--- | :--- | :--- | :--- |
| **[M1: Architecture](01-architecture/README.md)**<br>- [Restrict Tier Logons](01-architecture/restrict-tier-logons.md)<br>- [Restrict Management Protocols](01-architecture/restrict-mgmt-protocols.md)<br>- [Audit Privileged Groups](01-architecture/audit-privileged-groups.md)<br>- [Keep Functional Levels Up-To-Date](01-architecture/keep-functional-levels-up-to-date.md)<br>- [Default Policies Management](01-architecture/default-policies-recommendations.md)<br>- [Harden Domain Trusts](01-architecture/harden-domain-trusts.md) | ANSSI R1, R2, R3 (Tiering Model)<br>ANSSI R8 (Management subnets) | Section 18.2 (User Rights)<br>Section 19 (Windows Defender Firewall) | Privileged access boundaries, logon blocks, and management protocol restrictions. |
| **[M2: Domain Controllers](02-domain-controllers/README.md)**<br>- [Disable SMBv1](02-domain-controllers/disable-smbv1.md)<br>- [Disable Multicast Name Resolution](02-domain-controllers/disable-multicast-name-resolution.md)<br>- [Disable NTLMv1](02-domain-controllers/disable-ntlmv1.md)<br>- [Enforce LDAP Server Signing](02-domain-controllers/enforce-ldap-signing.md)<br>- [Enforce LDAP Channel Binding](02-domain-controllers/enforce-ldap-channel-binding.md)<br>- [Enable LSA Protection](02-domain-controllers/enable-lsa-protection.md)<br>- [Enable Credential Guard](02-domain-controllers/enable-credential-guard.md)<br>- [Disable Print Spooler Service](02-domain-controllers/disable-print-spooler.md)<br>- [Enforce SMB Message Signing](02-domain-controllers/enforce-smb-signing.md)<br>- [Restrict Kerberos Encryption Types](02-domain-controllers/restrict-kerberos-encryption.md)<br>- [Restrict Remote SAM API Access](02-domain-controllers/restrict-ntds-sam-api.md)<br>- [Disable Unnecessary Services](02-domain-controllers/disable-unnecessary-services.md)<br>- [Enable Kerberos Armoring](02-domain-controllers/enable-kerberos-armoring.md)<br>- [Restrict NTLM](02-domain-controllers/restrict-ntlm.md)<br>- [Migrate SYSVOL Replication to DFSR](02-domain-controllers/migrate-sysvol-replication-dfsr.md)<br>- [Harden adminSDHolder Permissions](02-domain-controllers/harden-adminsdholder-permissions.md)<br>- [Harden Microsoft DNS AD Container Permissions](02-domain-controllers/harden-dns-container-permissions.md)<br>- [Harden Virtualization Hosts for Domain Controllers](02-domain-controllers/harden-dc-virtualization-hosts.md)<br>- [Enforce RDP Restricted Admin Mode](02-domain-controllers/enforce-rdp-restricted-admin.md)<br>- [Windows Defender Antivirus DC Baseline](02-domain-controllers/defender-antivirus.md)<br>- [Configure AppLocker Policies on Domain Controllers](02-domain-controllers/configure-applocker-policies.md) | R19, R20 (LDAP Signing/Channel Binding), R22 (Spooler), R14 (LSA) | Section 2.3 (Security Options), Section 18.9 (System Services) | Credential Guard, Device Guard, Protocol Deprecation, AppLocker |
| **[M3: Identities & Services](03-identities-services/README.md)**<br>- [Enforce Fine-Grained Password Policies](03-identities-services/enforce-fgpp.md)<br>- [Enable LAPS](03-identities-services/enable-laps.md)<br>- [Implement Group Managed Service Accounts (gMSA)](03-identities-services/harden-service-accounts.md)<br>- [Restrict Kerberos Delegation](03-identities-services/restrict-kerberos-delegation.md)<br>- [Configure and Populate Protected Users Group](03-identities-services/configure-protected-users-group.md)<br>- [Rename and Disable Default Accounts](03-identities-services/harden-default-accounts.md)<br>- [Restrict Interactive Logons for Service Accounts](03-identities-services/restrict-service-account-logons.md)<br>- [Enforce User/Service Account Kerberos Encryption](03-identities-services/enforce-user-aes-encryption.md)<br>- [Enforce Kerberos Pre-Authentication](03-identities-services/enforce-kerberos-preauthentication.md)<br>- [Restrict Schema Administrators Group Membership](03-identities-services/restrict-schema-admins.md)<br>- [Enforce Accidental Deletion Protection on OUs](03-identities-services/prevent-accidental-deletion-ous.md)<br>- [Configure AD Authentication Silos](03-identities-services/configure-authentication-silos.md)<br>- [Clean Up adminCount Attribute Orphans](03-identities-services/cleanup-admincount-orphans.md)<br>- [Renew KDS Root Keys and gMSA Secrets](03-identities-services/renew-kds-keys-gmsa-secrets.md)<br>- [Harden ADCS PKI](03-identities-services/harden-adcs-pki.md)<br>- [Configure Point and Print Restrictions](03-identities-services/configure-point-and-print.md)<br>- [Disable Machine Account Quota](03-identities-services/disable-machine-account-quota.md)<br>- [Restrict Pre-Windows 2000 Compatible Access Group](03-identities-services/restrict-pre-windows-2000-compatible-access-group.md) | R9 (LAPS), R35 (gMSA), R15, R16 (Kerberos Delegation), R14 | Section 1.1 (Account Policies), Section 2.2.4 (User Rights), Section 2.3.10 (Network Security) | Password Complexity, Kerberos Encryption, LAPS Configuration, Point and Print restrictions, Machine Account Quota restriction, anonymous access restrictions |
| **[M4: Network & Firewall](04-network-firewall/README.md)**<br>- [Configure AD Port Matrix](04-network-firewall/configure-ad-port-matrix.md)<br>- [Restrict RPC Dynamic Ports](04-network-firewall/restrict-rpc-dynamic-ports.md)<br>- [Configure Workstation and Server Isolation](04-network-firewall/configure-workstation-isolation.md)<br>- [Configure IPsec Domain Isolation](04-network-firewall/configure-ipsec-domain-isolation.md)<br>- [Harden IPsec Cryptographic Configurations](04-network-firewall/harden-ipsec-cryptography.md)<br>- [Harden TLS Protocols, Cipher Suites, and Elliptic Curves](04-network-firewall/harden-tls-configuration.md)<br>- [Enforce SMBv3 Security](04-network-firewall/enforce-smbv3-security.md)<br>- [Configure Firewall Logging](04-network-firewall/configure-firewall-logging.md)<br>- [Configure Hardened UNC Paths](04-network-firewall/configure-hardened-unc-paths.md)<br>- [Harden WinRM Service and Restrict RPC Clients](04-network-firewall/harden-winrm-service.md) | R7 (IPsec), R8 (Administration subnets), R19 (Hardened UNC Paths) | Section 19 (Windows Defender Firewall) | Network Isolation, IPsec Domain Security, WinRM and RPC Client Hardening |
| **[M5: Logging & SIEM](05-logging-monitoring/README.md)**<br>- [Configure Advanced Security Audit Policies](05-logging-monitoring/configure-advanced-audit-policies.md)<br>- [Configure PowerShell and Command-Line Auditing](05-logging-monitoring/configure-powershell-and-command-line-auditing.md)<br>- [Deploy and Harden Microsoft Sysmon](05-logging-monitoring/deploy-and-harden-sysmon.md)<br>- [Configure Secure SIEM Log Shipping](05-logging-monitoring/configure-siem-log-shipping.md) | R48 (Audit Policy), R50 (PowerShell Log), R52 (Sysmon/WEC) | Section 9 (Audit Policy), Section 18.8 (PowerShell Logging) | Advanced Audit Policy, Transcription, Command Line Logs |
| **[M6: Ops & Maintenance](06-operations-maintenance/README.md)**<br>- [Secure Operations and Maintenance Baseline](06-operations-maintenance/ops-and-maintenance.md)<br>- [Enforce KRBTGT Password Rotation](06-operations-maintenance/enforce-krbtgt-password-rotation.md)<br>- [Enable and Configure AD Recycle Bin](06-operations-maintenance/enable-recycle-bin.md)<br>- [Establish and Maintain Group Policy ADMX Central Store](06-operations-maintenance/maintain-gpo-templates.md)<br>- [Implement Third-Party/Custom GPO Templates](06-operations-maintenance/use-third-party-templates.md)<br>- [Configure Dedicated WSUS for Tier 0](06-operations-maintenance/configure-dedicated-tier0-wsus.md) | R54 (AD Backup), R57 (Vulnerability Assessment) | Section 18.3 (System/Recovery Options) | Patch Management, Offline Disaster Recovery |
| **[M7: PAWs Hardening](07-paws/README.md)**<br>- [Configure AppLocker Policies for PAWs](07-paws/configure-applocker-policies.md)<br>- [Enable LSA Protection for PAWs](07-paws/enable-lsa-protection.md)<br>- [Restrict Local Administrators Group for PAWs](07-paws/restrict-local-administrators.md)<br>- [Enable BitLocker for PAWs](07-paws/enable-bitlocker.md)<br>- [UEFI Firmware Security](07-paws/configure-uefi-security.md)<br>- [Hardware Virtualization](07-paws/enable-hardware-virtualization-and-dma-protection.md)<br>- [Disable WPBT](07-paws/disable-wpbt.md)<br>- [Windows Defender Antivirus PAW Baseline](07-paws/defender-antivirus.md)<br>- [Configure User Rights Assignments for PAWs](07-paws/configure-user-rights-assignments.md)<br>- [Enable VBS and Credential Guard for PAWs](07-paws/enable-vbs-credential-guard.md)<br>- [Harden DMA and Physical Security for PAWs](07-paws/harden-dma-and-physical-security.md) | R58 (Use of PAWs) | Section 18.2.1 (LSA Protection), Section 18.8 (Device Guard/HVCI), Section 18.2.1.1 (BitLocker Startup Auth), Section 18.2.1.2 (Enhanced PINs), Section 18.2.1.3 (PIN Length) | VBS, AppLocker, Device Guard, and secure BitLocker disk encryption with Startup PIN. |
| **[M8: Endpoint Hardening](08-endpoints/README.md)**<br>- [Harden Network and Name Resolution](08-endpoints/harden-network-and-name-resolution.md)<br>- [UAC Policies](08-endpoints/configure-uac-policies.md)<br>- [Disable AutoPlay](08-endpoints/disable-autoplay-autorun.md)<br>- [Block Removable Storage](08-endpoints/block-removable-storage.md)<br>- [Restrict RDP](08-endpoints/restrict-rdp-access.md)<br>- [Restrict Local Admins](08-endpoints/restrict-local-admins.md)<br>- [Defender Antivirus](08-endpoints/defender-antivirus.md)<br>- [WSUS Configuration](08-endpoints/wsus-client-config.md)<br>- [Enable Secure Boot](08-endpoints/enable-secure-boot.md)<br>- [Enable VBS and Credential Guard](08-endpoints/enable-vbs-credential-guard.md)<br>- [Configure WDAC](08-endpoints/configure-wdac.md)<br>- [Enable BitLocker and Network Unlock](08-endpoints/enable-bitlocker.md)<br>- [UEFI Firmware Security](08-endpoints/configure-uefi-security.md)<br>- [Hardware Virtualization](08-endpoints/enable-hardware-virtualization-and-dma-protection.md)<br>- [Disable WPBT](08-endpoints/disable-wpbt.md)<br>- [Configure User Rights Assignments](08-endpoints/configure-user-rights-assignments.md)<br>- [Harden DMA and Physical Security](08-endpoints/harden-dma-and-physical-security.md)<br>- [Configure Account Policies](08-endpoints/configure-account-policies.md)<br>- [Configure User Profile Restrictions](08-endpoints/configure-user-profile-restrictions.md)<br>- [Block Outbound Traffic for Known LOLBins](08-endpoints/block-lolbins-outbound-traffic.md) | ANSSI R19 (Client signing)<br>ANSSI R9 (LAPS context)<br>ANSSI R58 (PAW / Endpoint encryption) | Section 9.1 (LLMNR)<br>Section 2.3.17 (UAC)<br>Section 18.3.1 (AutoPlay)<br>Section 18.9.82 (USB)<br>Section 18.2.1 (NLA)<br>Section 5.5 (Admins)<br>Section 18.9.47 (Defender)<br>Section 18.2.2 (WSUS)<br>Section 18.8.14.1 (Secure Boot/VBS)<br>Section 18.8.14.2 (Credential Guard)<br>Section 18.8.14.3 (WDAC)<br>Section 18.2.1.1 (Startup Auth)<br>Section 18.2.1.5 (Network Unlock) | Comprehensive Tier 2 workstation security configurations, network resolution controls, offline defense settings, disk encryption, and outbound firewall block rules. |

---

## Script Verification

To ensure that the markdown files contain valid links and that all embedded PowerShell code snippets are syntactically correct, you can run the verification script located in the root of this workspace.

### Running the Verification Script

Open a PowerShell console and run:

```powershell
.\Verify-ADHardeningDocs.ps1
```

The script parses all markdown documents, verifies internal relative links, and runs a syntax parser on all `powershell` code blocks without executing them.
