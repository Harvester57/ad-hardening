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
     * [REQ-ARCH-001 - Restrict Tier Logons](01-architecture/restrict-tier-logons.md)
     * [REQ-ARCH-002 - Restrict Administrative Management Protocols](01-architecture/restrict-mgmt-protocols.md)
     * [REQ-ARCH-003 - Audit Privileged Groups](01-architecture/audit-privileged-groups.md)
     * [REQ-ARCH-004 - Keep Domain and Forest Functional Levels Up-To-Date](01-architecture/keep-functional-levels-up-to-date.md)
     * [REQ-ARCH-005 - Default Domain and Domain Controllers Policies Management](01-architecture/default-policies-recommendations.md)
     * [REQ-ARCH-006 - Harden Active Directory Domain Trusts](01-architecture/harden-domain-trusts.md)
2. **[Module 2: Domain Controller Hardening](02-domain-controllers/README.md)**
   * Operating system-level DC security configuration.
   * Hardening controls:
     * [REQ-DC-001 - Disable SMBv1](02-domain-controllers/disable-smbv1.md)
     * [REQ-DC-002 - Disable Multicast Name Resolution](02-domain-controllers/disable-multicast-name-resolution.md)
     * [REQ-DC-003 - Disable NTLMv1](02-domain-controllers/disable-ntlmv1.md)
     * [REQ-DC-004 - Enforce LDAP Server Signing](02-domain-controllers/enforce-ldap-signing.md)
     * [REQ-DC-005 - Enforce LDAP Channel Binding](02-domain-controllers/enforce-ldap-channel-binding.md)
     * [REQ-DC-006 - Enable LSA Protection](02-domain-controllers/enable-lsa-protection.md)
     * [REQ-DC-007 - Disable Credential Guard](02-domain-controllers/disable-credential-guard.md)
     * [REQ-DC-008 - Disable Print Spooler Service](02-domain-controllers/disable-print-spooler.md)
     * [REQ-DC-009 - Enforce SMB Message Signing](02-domain-controllers/enforce-smb-signing.md)
     * [REQ-DC-010 - Restrict Kerberos Encryption Types](02-domain-controllers/restrict-kerberos-encryption.md)
     * [REQ-DC-011 - Restrict Remote SAM API Access](02-domain-controllers/restrict-ntds-sam-api.md)
     * [REQ-DC-012 - Disable Unnecessary Services on Domain Controllers](02-domain-controllers/disable-unnecessary-services.md)
     * [REQ-DC-013 - Enable Kerberos Armoring](02-domain-controllers/enable-kerberos-armoring.md)
     * [REQ-DC-014 - Restrict NTLM](02-domain-controllers/restrict-ntlm.md)
     * [REQ-DC-015 - Migrate SYSVOL Replication to DFSR](02-domain-controllers/migrate-sysvol-replication-dfsr.md)
     * [REQ-DC-016 - Harden adminSDHolder Permissions](02-domain-controllers/harden-adminsdholder-permissions.md)
     * [REQ-DC-017 - Harden Microsoft DNS AD Container Permissions](02-domain-controllers/harden-dns-container-permissions.md)
     * [REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](02-domain-controllers/harden-dc-virtualization-hosts.md)
     * [REQ-DC-019 - Enforce RDP Restricted Admin Mode](02-domain-controllers/enforce-rdp-restricted-admin.md)
     * [REQ-DC-020 - Windows Defender Antivirus Domain Controller Baseline and Exploit Guard](02-domain-controllers/defender-antivirus.md)
     * [REQ-DC-021 - Configure AppLocker Policies on Domain Controllers](02-domain-controllers/configure-applocker-policies.md)
3. **[Module 3: Identities & Services Hardening](03-identities-services/README.md)**
   * Administrative identity protection, credential hygiene, and service account hardening.
   * Hardening controls:
     * [REQ-ID-001 - Enforce Fine-Grained Password Policies](03-identities-services/enforce-fgpp.md)
     * [REQ-ID-002 - Enable Local Administrator Password Solution (LAPS)](03-identities-services/enable-laps.md)
     * [REQ-ID-003 - Implement Group Managed Service Accounts (gMSA)](03-identities-services/harden-service-accounts.md)
     * [REQ-ID-004 - Restrict Kerberos Delegation](03-identities-services/restrict-kerberos-delegation.md)
     * [REQ-ID-005 - Configure and Populate Protected Users Group](03-identities-services/configure-protected-users-group.md)
     * [REQ-ID-006 - Rename and Disable Default Administrator and Guest Accounts](03-identities-services/harden-default-accounts.md)
     * [REQ-ID-007 - Restrict Interactive Logons for Service Accounts](03-identities-services/restrict-service-account-logons.md)
     * [REQ-ID-008 - Enforce User and Service Account Kerberos Encryption (AES-Only)](03-identities-services/enforce-user-aes-encryption.md)
     * [REQ-ID-009 - Enforce Kerberos Pre-Authentication](03-identities-services/enforce-kerberos-preauthentication.md)
     * [REQ-ID-010 - Restrict Schema Administrators Group Membership](03-identities-services/restrict-schema-admins.md)
     * [REQ-ID-011 - Enforce Accidental Deletion Protection on Organizational Units](03-identities-services/prevent-accidental-deletion-ous.md)
     * [REQ-ID-012 - Configure Active Directory Authentication Silos and Policies](03-identities-services/configure-authentication-silos.md)
     * [REQ-ID-013 - Clean Up adminCount Attribute Orphans](03-identities-services/cleanup-admincount-orphans.md)
     * [REQ-ID-014 - Renew KDS Root Keys and gMSA Secrets](03-identities-services/renew-kds-keys-gmsa-secrets.md)
     * [REQ-ID-015 - Harden Active Directory Certificate Services (ADCS) and PKI](03-identities-services/harden-adcs-pki.md)
     * [REQ-ID-016 - Configure Point and Print, ELAM, Logon Screen, and Credentials Delegation](03-identities-services/configure-point-and-print.md)
     * [REQ-ID-017 - Disable Machine Account Quota](03-identities-services/disable-machine-account-quota.md)
     * [REQ-ID-018 - Restrict Pre-Windows 2000 Compatible Access Group](03-identities-services/restrict-pre-windows-2000-compatible-access-group.md)
4. **[Module 4: Network Configuration & Firewalling](04-network-firewall/README.md)**
   * Active Directory network boundaries, port configurations, and encryption/authentication configurations.
   * Hardening controls:
     * [REQ-NET-001 - Configure Active Directory Port Matrix](04-network-firewall/configure-ad-port-matrix.md)
     * [REQ-NET-002 - Restrict RPC Dynamic Ports](04-network-firewall/restrict-rpc-dynamic-ports.md)
     * [REQ-NET-003 - Configure Workstation and Server Isolation](04-network-firewall/configure-workstation-isolation.md)
     * [REQ-NET-004 - Configure IPsec Domain Isolation](04-network-firewall/configure-ipsec-domain-isolation.md)
     * [REQ-NET-005 - Harden IPsec Cryptographic Configurations](04-network-firewall/harden-ipsec-cryptography.md)
     * [REQ-NET-006 - Harden TLS Protocols, Cipher Suites, and Elliptic Curves](04-network-firewall/harden-tls-configuration.md)
     * [REQ-NET-007 - Enforce SMBv3 Security and Digitally Sign/Encrypt Communications](04-network-firewall/enforce-smbv3-security.md)
     * [REQ-NET-008 - Configure Firewall Logging and Operational Settings](04-network-firewall/configure-firewall-logging.md)
     * [REQ-NET-009 - Configure Hardened UNC Paths and LDAP Client Signing](04-network-firewall/configure-hardened-unc-paths.md)
     * [REQ-NET-010 - Harden WinRM Service and Restrict Remote RPC Clients](04-network-firewall/harden-winrm-service.md)
5. **[Module 5: Logging, Monitoring & SIEM](05-logging-monitoring/README.md)**
   * Entry point index for security log auditing, host monitoring, and centralized SIEM ingestion.
   * Hardening controls:
     * [REQ-LOG-001 - Configure Advanced Security Audit Policies](05-logging-monitoring/configure-advanced-audit-policies.md)
     * [REQ-LOG-002 - Configure PowerShell and Command-Line Auditing](05-logging-monitoring/configure-powershell-and-command-line-auditing.md)
     * [REQ-LOG-003 - Deploy and Harden Microsoft Sysmon](05-logging-monitoring/deploy-and-harden-sysmon.md)
     * [REQ-LOG-004 - Configure Secure SIEM Log Shipping](05-logging-monitoring/configure-siem-log-shipping.md)
6. **[Module 6: Secure Operations & Maintenance](06-operations-maintenance/README.md)**
   * AD System State backup, restore, and offline immutable storage.
   * Hardening controls:
     * [Secure Operations and Maintenance Baseline](06-operations-maintenance/ops-and-maintenance.md)
     * [REQ-OPS-001 - Enforce KRBTGT Password Rotation](06-operations-maintenance/enforce-krbtgt-password-rotation.md)
     * [REQ-OPS-002 - Enable and Configure the Active Directory Recycle Bin](06-operations-maintenance/enable-recycle-bin.md)
     * [REQ-OPS-003 - Establish and Maintain Group Policy ADMX Central Store](06-operations-maintenance/maintain-gpo-templates.md)
     * [REQ-OPS-004 - Implement Third-Party and Custom GPO Templates for COTS Hardening](06-operations-maintenance/use-third-party-templates.md)
     * [REQ-OPS-005 - Configure Dedicated WSUS for Tier 0](06-operations-maintenance/configure-dedicated-tier0-wsus.md)
7. **[Module 7: Privileged Access Workstations (PAWs) Hardening](07-paws/README.md)**
   * Physical and operating system isolation rules for administration devices.
   * Hardening controls:
     * [REQ-PAW-001 - Configure AppLocker Policies for PAWs](07-paws/configure-applocker-policies.md)
     * [REQ-PAW-002 - Enable LSA Protection for PAWs](07-paws/enable-lsa-protection.md)
     * [REQ-PAW-003 - Restrict Local Administrators Group for PAWs](07-paws/restrict-local-administrators.md)
     * [REQ-PAW-004 - Enforce BitLocker with TPM and Startup PIN for PAWs](07-paws/enable-bitlocker.md)
     * [REQ-PAW-005 - UEFI Firmware Security Hardening](07-paws/configure-uefi-security.md)
     * [REQ-PAW-006 - Enable Hardware Virtualization and DMA Protection](07-paws/enable-hardware-virtualization-and-dma-protection.md)
     * [REQ-PAW-007 - Disable Windows Platform Binary Table (WPBT)](07-paws/disable-wpbt.md)
     * [REQ-PAW-008 - Windows Defender Antivirus PAW Baseline and Exploit Guard](07-paws/defender-antivirus.md)
     * [REQ-PAW-009 - Configure User Rights Assignments for PAWs](07-paws/configure-user-rights-assignments.md)
     * [REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](07-paws/enable-vbs-credential-guard.md)
     * [REQ-PAW-011 - Harden DMA and Physical Security for PAWs](07-paws/harden-dma-and-physical-security.md)
8. **[Module 8: Endpoint Hardening](08-endpoints/README.md)**
   * Entry point index for Tier 2 workstation security.
   * Hardening controls:
     * [REQ-END-001 - Harden Network Parameters and Disable Legacy Name Resolution](08-endpoints/harden-network-and-name-resolution.md)
     * [REQ-END-002 - Configure User Account Control Policies](08-endpoints/configure-uac-policies.md)
     * [REQ-END-003 - Disable AutoPlay and AutoRun](08-endpoints/disable-autoplay-autorun.md)
     * [REQ-END-004 - Block Removable Storage](08-endpoints/block-removable-storage.md)
     * [REQ-END-005 - Restrict Remote Desktop Access](08-endpoints/restrict-rdp-access.md)
     * [REQ-END-006 - Restrict Local Administrators Group](08-endpoints/restrict-local-admins.md)
     * [REQ-END-007 - Windows Defender Antivirus Baseline and Exploit Guard](08-endpoints/defender-antivirus.md)
     * [REQ-END-008 - WSUS Client Configuration](08-endpoints/wsus-client-config.md)
     * [REQ-END-009 - Enable Secure Boot](08-endpoints/enable-secure-boot.md)
     * [REQ-END-010 - Enable VBS and Credential Guard](08-endpoints/enable-vbs-credential-guard.md)
     * [REQ-END-011 - Configure Windows Defender Application Control](08-endpoints/configure-wdac.md)
     * [REQ-END-012 - Enable BitLocker and Network Unlock](08-endpoints/enable-bitlocker.md)
     * [REQ-END-013 - UEFI Firmware Security Hardening](08-endpoints/configure-uefi-security.md)
     * [REQ-END-014 - Enable Hardware Virtualization and DMA Protection](08-endpoints/enable-hardware-virtualization-and-dma-protection.md)
     * [REQ-END-015 - Disable Windows Platform Binary Table (WPBT)](08-endpoints/disable-wpbt.md)
     * [REQ-END-016 - Configure User Rights Assignments](08-endpoints/configure-user-rights-assignments.md)
     * [REQ-END-017 - Harden DMA and Physical Security](08-endpoints/harden-dma-and-physical-security.md)
     * [REQ-END-018 - Configure Account and Password Policies](08-endpoints/configure-account-policies.md)
     * [REQ-END-019 - Configure User Profile Restrictions](08-endpoints/configure-user-profile-restrictions.md)
     * [REQ-END-022 - Block Outbound Traffic for Known LOLBins](08-endpoints/block-lolbins-outbound-traffic.md)

---

## Compliance Mapping Matrices

To ensure full transparency and compliance alignment, the unified compliance matrix has been split into three distinct, dedicated mapping matrices:

*   **[ANSSI Compliance Matrix](compliance/anssi.md)**: Detailed mapping to the recommendations of the ANSSI Active Directory Hardening Guide.
*   **[CIS Benchmarks Compliance Matrix](compliance/cis.md)**: Detailed mapping to the Center for Internet Security (CIS) Windows Server and Windows Client Benchmarks.
*   **[Microsoft Security Baselines Compliance Matrix](compliance/microsoft.md)**: Detailed mapping to Microsoft Security Baselines focus areas.

These detailed matrices extract each control from the respective guidelines and declare its compliance coverage status (**Covered** or **Not Covered**) alongside links to the corresponding technical controls in this guidebook.


---

## Script Verification

To ensure that the markdown files contain valid links and that all embedded PowerShell code snippets are syntactically correct, you can run the verification script located in the root of this workspace.

### Running the Verification Script

Open a PowerShell console and run:

```powershell
.\Verify-ADHardeningDocs.ps1
```

The script parses all markdown documents, verifies internal relative links, and runs a syntax parser on all `powershell` code blocks without executing them.
