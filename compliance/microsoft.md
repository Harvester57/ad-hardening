# Microsoft Security Baselines Compliance Mapping Matrix

This document maps the focus areas of the **Microsoft Security Baselines** (Domain Controller, Member Server, and Windows Client baselines) to the technical security controls present in this guidebook.

## Mapped Microsoft Security Baseline Focus Areas

| Focus Area | Baseline Requirement Description | Baseline Category | Status | Mapped Technical Control(s) |
| :--- | :--- | :--- | :--- | :--- |
| **Credential Guard** | Deploy Windows Defender Credential Guard to isolate and protect LSASS credentials (disabled on Domain Controllers as per Microsoft recommendations). | Credential Isolation | **Covered** | [REQ-DC-007](../02-domain-controllers/disable-credential-guard.md), [REQ-PAW-010](../07-paws/enable-vbs-credential-guard.md), [REQ-END-010](../08-endpoints/enable-vbs-credential-guard.md) |
| **LSA Protection** | Configure Local Security Authority (LSA) to run as a protected process (LSA Protection). | Credential Isolation | **Covered** | [REQ-DC-006](../02-domain-controllers/enable-lsa-protection.md), [REQ-PAW-002](../07-paws/enable-lsa-protection.md) |
| **Protocol Deprecation** | Disable legacy protocols (SMBv1, NTLMv1, digest authentication) across servers and endpoints. | Legacy Protocols | **Covered** | [REQ-DC-001](../02-domain-controllers/disable-smbv1.md), [REQ-DC-003](../02-domain-controllers/disable-ntlmv1.md), [REQ-DC-014](../02-domain-controllers/restrict-ntlm.md) |
| **AppLocker** | Deploy AppLocker application control policies to restrict unauthorized software execution. | Application Control | **Covered** | [REQ-DC-021](../02-domain-controllers/configure-applocker-policies.md), [REQ-PAW-001](../07-paws/configure-applocker-policies.md) |
| **Windows Defender Application Control** | Deploy Windows Defender Application Control (WDAC) and Driver Blocklists. | Application Control | **Covered** | [REQ-DC-022](../02-domain-controllers/enable-wdac-driver-blocklist.md), [REQ-PAW-012](../07-paws/enable-wdac-driver-blocklist.md), [REQ-END-011](../08-endpoints/configure-wdac.md) |
| **BitLocker** | Enforce BitLocker drive encryption with TPM and Startup PIN configurations. | Data Protection | **Covered** | [REQ-PAW-004](../07-paws/enable-bitlocker.md), [REQ-END-012](../08-endpoints/enable-bitlocker.md) |
| **DMA Protection** | Enable hardware virtualization-based security and Kernel DMA Protection. | Hardware Integrity | **Covered** | [REQ-PAW-006](../07-paws/enable-hardware-virtualization-and-dma-protection.md), [REQ-END-014](../08-endpoints/enable-hardware-virtualization-and-dma-protection.md) |
| **Secure Boot** | Enforce UEFI Secure Boot and hardware platform security settings. | Hardware Integrity | **Covered** | [REQ-PAW-005](../07-paws/configure-uefi-security.md), [REQ-END-009](../08-endpoints/enable-secure-boot.md) |
| **Audit Policies** | Configure advanced security audit policies (DC, member server, and client baselines). | Auditing & Logging | **Covered** | [REQ-LOG-001](../05-logging-monitoring/configure-advanced-audit-policies.md) |
| **PowerShell Logging** | Configure PowerShell script block logging and transcription. | Auditing & Logging | **Covered** | [REQ-LOG-002](../05-logging-monitoring/configure-powershell-and-command-line-auditing.md) |
| **UAC Policies** | Configure User Account Control (UAC) baseline settings. | Account Controls | **Covered** | [REQ-END-002](../08-endpoints/configure-uac-policies.md) |
| **Removable Storage** | Deploy GPOs to block external removable storage devices (USB mass storage). | Data Protection | **Covered** | [REQ-END-004](../08-endpoints/block-removable-storage.md) |
| **Point and Print** | Configure Point and Print restrictions to prevent PrintNightmare exploits. | Services Hardening | **Covered** | [REQ-ID-016](../03-identities-services/configure-point-and-print.md) |
| **SYSVOL replication** | Migrate SYSVOL replication from FRS to DFS Replication (DFSR). | DC Hardening | **Covered** | [REQ-DC-015](../02-domain-controllers/migrate-sysvol-replication-dfsr.md) |
| **adminSDHolder** | Harden adminSDHolder object permissions to prevent privilege persistence. | DC Hardening | **Covered** | [REQ-DC-016](../02-domain-controllers/harden-adminsdholder-permissions.md), [REQ-DC-024](../02-domain-controllers/configure-dsheuristics.md) |
| **Services minimization** | Disable unnecessary system services on Domain Controllers. | DC Hardening | **Covered** | [REQ-DC-012](../02-domain-controllers/disable-unnecessary-services.md) |
| **dSHeuristics Hardening** | Configure the forest-wide dSHeuristics attribute to block anonymous operations, secure adminSDHolder, and enforce KB5008383 protections. | DC Hardening | **Covered** | [REQ-DC-024](../02-domain-controllers/configure-dsheuristics.md) |

## Microsoft Baseline Controls Outside Guidebook Scope

The following Microsoft Security Baseline recommendations are not covered by this guidebook as they are more suited for cloud-managed, internet-connected, or hybrid environments:

| Focus Area | Baseline Requirement Description | Category | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Microsoft Defender for Endpoint** | Cloud-based EDR enrollment and configuration | Endpoint Defense | **Not Covered** | Out of scope due to the strict air-gapped (offline) requirement of the environment. |
| **Windows Update for Business** | Cloud-based patch management and updates | Patch Management | **Not Covered** | Out of scope. Patching must be managed via offline WSUS tiering. |
| **Microsoft Defender SmartScreen** | Cloud-based reputation screening for downloads | Edge / Web Security | **Not Covered** | No internet connection is present to contact Microsoft reputation services. |