# Module 7: Privileged Access Workstations (PAWs) Hardening

This directory contains the physical isolation policies and operating system security configurations required to protect Tier 0 administrative workstations.

## Technical Hardening Controls

1. **[REQ-PAW-001 - Configure AppLocker Policies for PAWs](configure-applocker-policies.md)**
   Enforces strict AppLocker application control policies, restricting execution of unauthorized binaries to approved administrative groups.

2. **[REQ-PAW-002 - Enable LSA Protection for PAWs](enable-lsa-protection.md)**
   Configures LSASS to run as a protected process (PPL) to block credential dumping tools from harvesting secrets from LSA memory.

3. **[REQ-PAW-003 - Restrict Local Administrators Group for PAWs](restrict-local-administrators.md)**
   Restricts and audits membership in the local Administrators group on PAWs to prevent unauthorized local administrative access.

4. **[REQ-PAW-004 - Enforce BitLocker with TPM and Startup PIN for PAWs](enable-bitlocker.md)**
   Configures highly stringent BitLocker policies specifically for PAWs, requiring TPM + pre-boot Startup PIN (no Network Unlock allowed), disabling sleep/standby states (S1-S3) to prevent DMA attacks, enabling Kernel DMA Protection, and enforcing enhanced PIN rules and automatic AD recovery password rotation.

5. **[REQ-PAW-005 - UEFI Firmware Security Hardening](configure-uefi-security.md)**
   Enforces UEFI firmware locking, setting a strong BIOS administrator password, disabling CSM/Legacy boot, locking the boot order, and protecting against BIOS rollbacks.

6. **[REQ-PAW-006 - Enable Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md)**
   Enables hardware CPU virtualization, IOMMU/DMA protection at the firmware level, and TPM 2.0 to provide the necessary platform integrity foundation for Virtualization-Based Security (VBS).

7. **[REQ-PAW-007 - Disable Windows Platform Binary Table (WPBT)](disable-wpbt.md)**
   Disables execution of binaries supplied by the Windows Platform Binary Table (WPBT) ACPI firmware table to mitigate boot-level security bypasses.

8. **[REQ-PAW-008 - Windows Defender Antivirus PAW Baseline and Exploit Guard](defender-antivirus.md)**
   Configures Windows Defender Antivirus on PAWs, enabling real-time scanning, behavioral monitoring, preventing local exclusion modifications, enforcing all ASR rules in strict Block mode, activating Tamper Protection, and enabling AppContainer sandbox isolation.

9. **[REQ-PAW-009 - Configure User Rights Assignments for PAWs](configure-user-rights-assignments.md)**
   Restricts critical user rights assignments (URAs) such as debugging programs, token impersonation, and denying network/interactive logon permissions for standard accounts on PAWs.

10. **[REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](enable-vbs-credential-guard.md)**
    Configures Virtualization-Based Security (VBS), Credential Guard (with UEFI Lock), System Guard Secure Launch, and memory protections to shield LSASS from credential dumping attacks on PAWs.

11. **[REQ-PAW-011 - Harden DMA and Physical Security for PAWs](harden-dma-and-physical-security.md)**
    Mitigates physical access threat vectors by disabling sleep standby states (S1-S3), disabling external DMA device enumeration under lock, enforcing a strict block-all device enumeration policy, and blocking legacy SBP-2 device classes.

12. **[REQ-PAW-012 - Enable WDAC Driver Blocklist](enable-wdac-driver-blocklist.md)**
    Enforces the Microsoft Vulnerable Driver Blocklist using Windows Defender Application Control (WDAC) to protect the kernel from Bring Your Own Vulnerable Driver (BYOVD) attacks.

13. **[REQ-PAW-013 - Configure Account and Password Policies for PAWs](configure-account-policies.md)**
    Configures robust local account lockout, local password complexity, and 20-character minimum length policies, and references Active Directory Fine-Grained Password Policies (FGPP) for Tier 0 Administrators.

14. **[REQ-PAW-014 - Configure Early Launch Antimalware (ELAM) Policy for PAWs](configure-elam.md)**
    Configures the Early Launch Antimalware (ELAM) driver initialization policy to ensure only signed, trusted boot drivers execute.

15. **[REQ-PAW-015 - Configure Secure Printing and Print Spooler Policies for PAWs](configure-printing-and-spooler.md)**
    Enforces disabling the Print Spooler service and configuring Point and Print restrictions to prevent print-related exploits.
