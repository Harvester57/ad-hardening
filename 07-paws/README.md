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

16. **[REQ-PAW-016 - Configure Untrusted Font Blocking for PAWs](configure-untrusted-font-blocking.md)**
    Configures the Untrusted Font Blocking mitigation on PAWs to prevent font parsing exploits.

17. **[REQ-PAW-017 - Configure svchost.exe Mitigation Options for PAWs](configure-svchost-mitigation.md)**
    Configures svchost.exe mitigation options on PAWs to restrict binary loading to Microsoft-signed code and block dynamic code execution.

18. **[REQ-PAW-018 - Enable Kernel-Mode Hardware-Enforced Stack Protection for PAWs](enable-kernel-shadow-stacks.md)**
    Configures Kernel-mode Hardware-enforced Stack Protection to enforce hardware-backed control-flow integrity and mitigate kernel Return-Oriented Programming (ROP) execution hijacks.

19. **[REQ-PAW-019 - Harden Network Parameters and Disable Legacy Name Resolution](harden-network-and-name-resolution.md)**
    Disables Link-Local Multicast Name Resolution (LLMNR), NetBIOS over TCP/IP, and mDNS, and secures TCP/IP parameters on PAWs to prevent credential harvesting and protocol exploits.

20. **[REQ-PAW-020 - Configure User Account Control Policies for PAWs](configure-uac-policies.md)**
    Enforces maximum UAC security behavior, requiring credential entry on the secure desktop for administrators and automatically denying elevation prompts.

21. **[REQ-PAW-021 - Disable AutoPlay and AutoRun for PAWs](disable-autoplay-autorun.md)**
    Turns off AutoPlay and AutoRun features across all drive types to prevent automatic execution of files and payloads from external media.

22. **[REQ-PAW-022 - Disable Incoming Remote Desktop Access for PAWs](restrict-rdp-access.md)**
    Strictly denies incoming RDP and Remote Assistance connections to administrative workstations to block lateral movement.

23. **[REQ-PAW-023 - WSUS Client Configuration for PAWs](wsus-client-config.md)**
    Enforces update client registry baselines to ensure workstations pull OS patches and security signatures exclusively from the local, offline WSUS server.

24. **[REQ-PAW-024 - Configure User Profile and System Restrictions for PAWs](configure-user-profile-restrictions.md)**
    Locks down user profile registry settings and key system security policies including inactivity timeouts, secondary logon, and ASLR force.

25. **[REQ-PAW-025 - Configure Exploit Protection Profile for PAWs](configure-exploit-protection.md)**
    Configures and enforces a system-wide Microsoft Defender Exploit Protection profile to apply advanced memory mitigations (DEP, ASLR, CFG, SEHOP, Heap Integrity) on all PAWs.

26. **[REQ-PAW-026 - Restrict Safe Mode Access to Administrators on PAWs](disable-safe-mode-for-standard-users.md)**
    Prevents standard (non-administrative) users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

27. **[REQ-PAW-027 - Configure Windows Defender Firewall and Block LOLBins for PAWs](configure-windows-firewall.md)**
    Configures host firewall profiles and outbound rules to block known Living Off the Land Binaries (LOLBins) from initiating outgoing network connections.

28. **[REQ-PAW-028 - Disable Unnecessary System Services for PAWs](disable-unnecessary-system-services.md)**
    Disables unnecessary and high-risk system services to minimize the attack surface of administrative endpoints.

29. **[REQ-PAW-029 - Configure System Administrative Templates for PAWs](configure-system-administrative-templates.md)**
    Enforces custom administrative template settings including SMBv1 driver blocks and event log size extensions.

30. **[REQ-PAW-030 - Enable UEFI Secure Boot for PAWs](enable-secure-boot.md)**
    Mandates hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on the operating system for PAWs.

31. **[REQ-PAW-031 - Enforce Smart Card Logon for PAWs](enforce-smartcard-logon-paws.md)**
    Enforces the 'Interactive logon: Require smart card' GPO policy locally to suppress username/password fields and force hardware-bound authentication.

32. **[REQ-PAW-032 - Disable Unused Windows Features and PowerShell 2.0 Engine](disable-unused-features.md)**
    Disables legacy, unused Windows optional features, including PowerShell 2.0, .NET Framework 3.5, and SMBv1 to minimize the workstation attack surface.

33. **[REQ-PAW-033 - Configure Microsoft Office Security and Block OLE Packages](configure-office-security.md)**
    Blocks VBA macros from running in Office files downloaded from the Internet, enforces macro digital signing warnings, and disables OLE Package execution in Outlook to prevent initial access exploits.

34. **[REQ-PAW-034 - Disable Windows Script Host and Remap Scripting Extensions](disable-windows-script-host.md)**
    Disables Windows Script Host execution globally and remaps standard scripting extensions (.vbs, .js, etc.) to open in Notepad by default to prevent execution by double-click.

35. **[REQ-PAW-035 - Configure Secure Boot Revocations and Bootloader Updates for PAWs](configure-secure-boot-revocations.md)**
    Configures and enforces BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware for PAWs.



