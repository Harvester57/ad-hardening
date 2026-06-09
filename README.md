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

## Table of Contents

The guidebook is organized into eight functional modules:

1. **[Module 1: Architecture & Administrative Tiering](01-architecture/README.md)**
   * Entry point index and technical treatise on Active Directory tiering and administrative boundaries.
   * Hardening controls:
     * [Restrict Tier Logons](01-architecture/restrict-tier-logons.md)
     * [Restrict Administrative Management Protocols](01-architecture/restrict-mgmt-protocols.md)
     * [Audit Privileged Groups](01-architecture/audit-privileged-groups.md)
2. **[Module 2: Domain Controller Hardening](02-domain-controllers/README.md)**
   * Operating system-level DC security configuration.
   * Disabling legacy protocols (SMBv1, LLMNR, NBT-NS, NTLMv1).
   * Enforcing LDAP signing, LDAP channel binding, LSA protection, and Credential Guard.
   * Securing critical services (Print Spooler disable).
3. **[Module 3: Identities & Services Hardening](03-identities-services/README.md)**
   * Fine-Grained Password Policies (FGPP).
   * Local Administrator Password Solution (LAPS) in offline environments.
   * Group Managed Service Accounts (gMSA) lifecycle.
   * Kerberos encryption hardening (AES enforcement) and delegation restrictions.
4. **[Module 4: Network Configuration & Firewalling](04-network-firewall/README.md)**
   * Active Directory Port Matrix (replication, clients, management).
   * Workstation Isolation policies using Windows Defender Firewall via GPO.
   * Dedicated management subnet architecture.
   * IPsec Transport Mode for AD domain traffic isolation.
5. **[Module 5: Logging, Monitoring & SIEM](05-logging-monitoring/README.md)**
   * Advanced Security Audit Policy configuration.
   * Command Line Auditing and PowerShell Transcription.
   * Sysmon configuration, Winlogbeat, and Wazuh shippers in offline SIEM deployments.
6. **[Module 6: Secure Operations & Maintenance](06-operations-maintenance/README.md)**
   * AD System State backup, restore, and offline immutable storage.
   * Offline patch management (WSUS import/export, manual cab installation).
   * Continuous offline security assessments (PingCastle, ADRecon, and scripts).
7. **[Module 7: Privileged Access Workstations (PAWs) Hardening](07-paws/README.md)**
   * Physical and operating system isolation rules for administration devices.
   * [Enable BitLocker for PAWs](07-paws/enable-bitlocker.md)
   * Credential Guard, Device Guard (HVCI), and AppLocker rules.
   * PowerShell scripts to audit VBS, AppLocker, local Administrators group, and BitLocker.
8. **[Module 8: Endpoint Hardening](08-endpoints/README.md)**
   * Entry point index for Tier 2 workstation security.
   * Hardening controls:
     * [Disable Legacy Name Resolution](08-endpoints/disable-legacy-name-resolution.md)
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

---

## Compliance Mapping Matrix

Below is a cross-reference matrix mapping each guidebook module to specific guidelines from **ANSSI**, **CIS**, and **Microsoft Security Baselines**:

| Module | ANSSI AD Guide Recommendation | CIS Windows Server/10 Benchmark | Microsoft Security Baseline Focus |
| :--- | :--- | :--- | :--- |
| **[M1: Architecture](01-architecture/README.md)**<br>- [Restrict Tier Logons](01-architecture/restrict-tier-logons.md)<br>- [Restrict Management Protocols](01-architecture/restrict-mgmt-protocols.md)<br>- [Audit Privileged Groups](01-architecture/audit-privileged-groups.md) | ANSSI R1, R2, R3 (Tiering Model)<br>ANSSI R8 (Management subnets) | Section 18.2 (User Rights)<br>Section 19 (Windows Defender Firewall) | Privileged access boundaries, logon blocks, and management protocol restrictions. |
| **[M2: Domain Controllers](02-domain-controllers/README.md)** | R19, R20 (LDAP Signing/Channel Binding), R22 (Spooler), R14 (LSA) | Section 2.3 (Security Options), Section 18.9 (System Services) | Credential Guard, Device Guard, Protocol Deprecation |
| **[M3: Identities & Services](03-identities-services/README.md)** | R9 (LAPS), R35 (gMSA), R15, R16 (Kerberos Delegation) | Section 1.1 (Account Policies), Section 2.3.10 (Network Security) | Password Complexity, Kerberos Encryption, LAPS Configuration |
| **[M4: Network & Firewall](04-network-firewall/README.md)** | R7 (IPsec), R8 (Administration subnets) | Section 19 (Windows Defender Firewall) | Network Isolation, IPsec Domain Security |
| **[M5: Logging & SIEM](05-logging-monitoring/README.md)** | R48 (Audit Policy), R50 (PowerShell Log), R52 (Sysmon/WEC) | Section 9 (Audit Policy), Section 18.8 (PowerShell Logging) | Advanced Audit Policy, Transcription, Command Line Logs |
| **[M6: Ops & Maintenance](06-operations-maintenance/README.md)** | R54 (AD Backup), R57 (Vulnerability Assessment) | Section 18.3 (System/Recovery Options) | Patch Management, Offline Disaster Recovery |
| **[M7: PAWs Hardening](07-paws/README.md)**<br>- [Enable BitLocker for PAWs](07-paws/enable-bitlocker.md) | R58 (Use of PAWs) | Section 18.2.1 (LSA Protection), Section 18.8 (Device Guard/HVCI), Section 18.2.1.1 (BitLocker Startup Auth), Section 18.2.1.2 (Enhanced PINs), Section 18.2.1.3 (PIN Length) | VBS, AppLocker, Device Guard, and secure BitLocker disk encryption with Startup PIN. |
| **[M8: Endpoint Hardening](08-endpoints/README.md)**<br>- [Disable Name Resolution](08-endpoints/disable-legacy-name-resolution.md)<br>- [UAC Policies](08-endpoints/configure-uac-policies.md)<br>- [Disable AutoPlay](08-endpoints/disable-autoplay-autorun.md)<br>- [Block Removable Storage](08-endpoints/block-removable-storage.md)<br>- [Restrict RDP](08-endpoints/restrict-rdp-access.md)<br>- [Restrict Local Admins](08-endpoints/restrict-local-admins.md)<br>- [Defender Antivirus](08-endpoints/defender-antivirus.md)<br>- [WSUS Configuration](08-endpoints/wsus-client-config.md)<br>- [Enable Secure Boot](08-endpoints/enable-secure-boot.md)<br>- [Enable VBS and Credential Guard](08-endpoints/enable-vbs-credential-guard.md)<br>- [Configure WDAC](08-endpoints/configure-wdac.md)<br>- [Enable BitLocker and Network Unlock](08-endpoints/enable-bitlocker.md) | ANSSI R19 (Client signing)<br>ANSSI R9 (LAPS context)<br>ANSSI R58 (PAW / Endpoint encryption) | Section 9.1 (LLMNR)<br>Section 2.3.17 (UAC)<br>Section 18.3.1 (AutoPlay)<br>Section 18.9.82 (USB)<br>Section 18.2.1 (NLA)<br>Section 5.5 (Admins)<br>Section 18.9.47 (Defender)<br>Section 18.2.2 (WSUS)<br>Section 18.8.14.1 (Secure Boot/VBS)<br>Section 18.8.14.2 (Credential Guard)<br>Section 18.8.14.3 (WDAC)<br>Section 18.2.1.1 (Startup Auth)<br>Section 18.2.1.5 (Network Unlock) | Comprehensive Tier 2 workstation security configurations, network resolution controls, offline defense settings, and disk encryption. |

---

## Script Verification

To ensure that the markdown files contain valid links and that all embedded PowerShell code snippets are syntactically correct, you can run the verification script located in the root of this workspace.

### Running the Verification Script

Open a PowerShell console and run:

```powershell
.\Verify-ADHardeningDocs.ps1
```

The script parses all markdown documents, verifies internal relative links, and runs a syntax parser on all `powershell` code blocks without executing them.
