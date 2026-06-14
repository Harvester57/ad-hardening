# CIS Benchmarks Compliance Mapping Matrix

This document maps the **CIS Benchmarks** sections for Windows Server (2016, 2019, 2022) and Windows 10/11 Client systems to the technical security controls present in this guidebook.

## Mapped CIS Benchmark Sections

| CIS Section | Section Title / Scope | Benchmark Category | Status | Mapped Technical Control(s) |
| :--- | :--- | :--- | :--- | :--- |
| **1.1** | Password Policy (Complexity, Length, Age, History) | Account Policies | **Covered** | [REQ-ID-001](../03-identities-services/enforce-fgpp.md), [REQ-PAW-013](../07-paws/configure-account-policies.md), [REQ-END-018](../08-endpoints/configure-account-policies.md) |
| **1.2** | Account Lockout Policy (Threshold, Duration) | Account Policies | **Covered** | [REQ-PAW-013](../07-paws/configure-account-policies.md), [REQ-END-018](../08-endpoints/configure-account-policies.md) |
| **1.3** | Kerberos Policy (Ticket Lifetimes, Clock Tolerance) | Account Policies | **Covered** | [REQ-END-018](../08-endpoints/configure-account-policies.md) |
| **2.2** | User Rights Assignment (Deny logons, Allow logons, DC Operator Restrictions) | Local Policies | **Covered** | [REQ-ARCH-001](../01-architecture/restrict-tier-logons.md), [REQ-ID-007](../03-identities-services/restrict-service-account-logons.md), [REQ-DC-023](../02-domain-controllers/configure-user-rights-assignments.md), [REQ-PAW-009](../07-paws/configure-user-rights-assignments.md), [REQ-END-016](../08-endpoints/configure-user-rights-assignments.md) |
| **2.3** | Security Options (LSA, LAN Manager, LDAP Signing, SMB Signing) | Local Policies | **Covered** | [REQ-DC-003](../02-domain-controllers/disable-ntlmv1.md), [REQ-DC-004](../02-domain-controllers/enforce-ldap-signing.md), [REQ-DC-005](../02-domain-controllers/enforce-ldap-channel-binding.md), [REQ-DC-006](../02-domain-controllers/enable-lsa-protection.md), [REQ-DC-009](../02-domain-controllers/enforce-smb-signing.md), [REQ-DC-010](../02-domain-controllers/restrict-kerberos-encryption.md), [REQ-DC-011](../02-domain-controllers/restrict-ntds-sam-api.md), [REQ-DC-014](../02-domain-controllers/restrict-ntlm.md), [REQ-DC-024](../02-domain-controllers/configure-dsheuristics.md) |
| **9.1** | Windows Defender Firewall Profiles (Domain, Private, Public) | Firewall | **Covered** | [REQ-NET-001](../04-network-firewall/configure-ad-port-matrix.md), [REQ-NET-008](../04-network-firewall/configure-firewall-logging.md) |
| **18.2** | Local Administrator Password Solution (LAPS) settings | Administrative Templates | **Covered** | [REQ-ID-002](../03-identities-services/enable-laps.md) |
| **18.3** | AutoPlay and AutoRun settings | Administrative Templates | **Covered** | [REQ-END-003](../08-endpoints/disable-autoplay-autorun.md) |
| **18.8** | PowerShell Logging, Device Guard, and Virtualization-Based Security | Administrative Templates | **Covered** | [REQ-LOG-002](../05-logging-monitoring/configure-powershell-and-command-line-auditing.md), [REQ-PAW-006](../07-paws/enable-hardware-virtualization-and-dma-protection.md), [REQ-PAW-010](../07-paws/enable-vbs-credential-guard.md), [REQ-END-010](../08-endpoints/enable-vbs-credential-guard.md) |
| **18.9** | System Services (Print Spooler), AppLocker, WDAC, and GP Refresh settings | Administrative Templates | **Covered** | [REQ-ARCH-005](../01-architecture/default-policies-recommendations.md), [REQ-DC-001](../02-domain-controllers/disable-smbv1.md), [REQ-DC-008](../02-domain-controllers/disable-print-spooler.md), [REQ-DC-021](../02-domain-controllers/configure-applocker-policies.md), [REQ-PAW-001](../07-paws/configure-applocker-policies.md), [REQ-END-011](../08-endpoints/configure-wdac.md) |
| **19.1** | Windows Defender Firewall port configurations and isolation rules | Firewall Advanced Security | **Covered** | [REQ-NET-001](../04-network-firewall/configure-ad-port-matrix.md), [REQ-NET-003](../04-network-firewall/configure-workstation-isolation.md), [REQ-NET-008](../04-network-firewall/configure-firewall-logging.md) |
| **Public Key** | Encrypting File System (EFS) Settings | Public Key Policies | **Covered** | [REQ-ARCH-005](../01-architecture/default-policies-recommendations.md) |

## CIS Benchmark Sections Outside Active Directory Scope

The following CIS Benchmark sections are not covered by this guidebook because they concern standalone workstation settings, user-level privacy options, or non-security features:

| Section | Title / Scope | Category | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **18.5** | Network / WLAN Settings | Wireless Connections | **Not Covered** | Air-gapped environments typically run on physical cabling or specialized networking. |
| **18.8.2** | Toast Notifications / Cortana Settings | User Experience | **Not Covered** | Operational/productivity settings, low security impact. |
| **18.8.3** | Spotlight / Telemetry Options | User Experience | **Not Covered** | Privacy-related settings, not directly related to Active Directory security. |
| **18.9.1** | Background Intelligent Transfer Service | System Services | **Not Covered** | General operating system background task tuning. |