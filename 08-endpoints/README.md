# Module 8: Endpoint Hardening

This directory defines the technical security baselines for standard client workstations (Tier 2 endpoints) operating in isolated, air-gapped domains. 

To prevent initial access and lateral movement, the following unitary technical hardening controls must be implemented:

## Technical Hardening Controls

1. **[REQ-END-001 - Harden Network Parameters and Disable Legacy Name Resolution](harden-network-and-name-resolution.md)**
   Disables Link-Local Multicast Name Resolution (LLMNR), NetBIOS over TCP/IP, and mDNS, and secures TCP/IP parameters to prevent local credential harvesting and protocol exploits.

2. **[REQ-END-002 - Configure User Account Control Policies](configure-uac-policies.md)**
   Enforces maximum UAC security behavior, requiring credential entry on the secure desktop for administrators and automatically denying elevation prompts for standard users.

3. **[REQ-END-003 - Disable AutoPlay and AutoRun](disable-autoplay-autorun.md)**
   Turns off AutoPlay and AutoRun features across all drive types to prevent automatic execution of files and payloads from external media.

4. **[REQ-END-004 - Block Removable Storage](block-removable-storage.md)**
   Blocks read and write access to USB drives and other removable media classes to mitigate data leakage and malware propagation.

5. **[REQ-END-005 - Restrict Remote Desktop Access](restrict-rdp-access.md)**
   Blocks incoming RDP connections to standard workstations by default, or restricts allowed connection sources to authorized administrative subnets with Network Level Authentication (NLA) enabled.

6. **[REQ-END-006 - Restrict Local Administrators Group](restrict-local-admins.md)**
   Locks down local workstation administrative privileges, removing standard domain users and enforcing administrative segregation utilizing LAPS.

7. **[REQ-END-007 - Windows Defender Antivirus Baseline and Exploit Guard](defender-antivirus.md)**
   Configures Windows Defender Antivirus, enabling real-time scanning, behavioral monitoring, preventing local exclusion modifications, enforcing Attack Surface Reduction (ASR) rules, activating Tamper Protection, and enabling AppContainer sandbox isolation.

8. **[REQ-END-008 - WSUS Client Configuration](wsus-client-config.md)**
   Enforces update client registry baselines to ensure workstations pull OS patches and security signatures exclusively from the local, offline WSUS server.

9. **[REQ-END-009 - Enable UEFI Secure Boot](enable-secure-boot.md)**
   Mandates hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on the operating system.

10. **[REQ-END-010 - Enable VBS and Credential Guard](enable-vbs-credential-guard.md)**
    Activates Virtualization-Based Security (VBS) and Credential Guard to protect password hashes and Kerberos tickets in an isolated virtual container, mitigating LSASS dumping.

11. **[REQ-END-011 - Configure Windows Defender Application Control](configure-wdac.md)**
    Deploys application control baselines and the Microsoft Vulnerable Driver Blocklist to enforce code integrity policies, restricting the system to run only signed, authorized binaries, scripts, and secure drivers.

12. **[REQ-END-012 - Enable BitLocker and Network Unlock](enable-bitlocker.md)**
    Enforces full disk encryption with TPM and enables secure Network Unlock capabilities for standard client workstations.

13. **[REQ-END-013 - UEFI Firmware Security Hardening](configure-uefi-security.md)**
    Enforces password protection, disables Compatibility Support Module (CSM)/Legacy Boot, locks boot order, and configures secure firmware update policies.

14. **[REQ-END-014 - Enable Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md)**
    Enables CPU virtualization (VT-x/AMD-V) and IOMMU (VT-d/AMD-Vi) to provide the hardware-rooted platform integrity required for VBS and Kernel DMA protection.

15. **[REQ-END-015 - Disable Windows Platform Binary Table (WPBT)](disable-wpbt.md)**
    Disables execution of binaries supplied by the Windows Platform Binary Table (WPBT) ACPI firmware table to mitigate boot-level security bypasses.

16. **[REQ-END-016 - Configure User Rights Assignments](configure-user-rights-assignments.md)**
    Restricts critical user rights assignments (URAs) such as debugging programs, token impersonation, and local logon permissions on standard client endpoints.

17. **[REQ-END-017 - Harden DMA and Physical Security](harden-dma-and-physical-security.md)**
    Mitigates physical access threat vectors by disabling standby sleep states (S1-S3), disabling external DMA device enumeration under lock, blocking legacy SBP-2 device classes, and denying write access to removable drives without BitLocker protection.

18. **[REQ-END-018 - Configure Account and Password Policies](configure-account-policies.md)**
    Enforces local and domain-wide account settings, including account lockout thresholds, lockout observation windows, smart card removal actions, and disabling reversible password encryption.

19. **[REQ-END-019 - Configure User Profile Restrictions](configure-user-profile-restrictions.md)**
    Locks down user profile registry settings (HKCU) to disable toast notifications on the lock screen and block third-party application suggestions.

20. **[REQ-END-020 - Configure Exploit Protection Profile](configure-exploit-protection.md)**
    Configures and enforces a system-wide Microsoft Defender Exploit Protection profile to apply advanced memory mitigations (DEP, ASLR, CFG, SEHOP, Heap Integrity) on all endpoints.

21. **[REQ-END-021 - Restrict Safe Mode Access to Administrators](disable-safe-mode-for-standard-users.md)**
    Prevents standard (non-administrative) users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

22. **[REQ-END-022 - Configure Windows Defender Firewall and Block LOLBins](configure-windows-firewall.md)**
    Configures Domain, Private, and Public firewall profile states, logging, and notifications, and enforces outbound rules to block known Living Off the Land Binaries (LOLBins) from initiating outgoing network connections.

23. **[REQ-END-023 - Enable LSA Protection with UEFI Lock](enable-lsa-protection.md)**
    Configures the LSA Protection setting to run the LSASS process as a Protected Process Light (PPL) with UEFI Lock, preventing credential harvesting from LSASS memory.

24. **[REQ-END-024 - Disable Unnecessary System Services](disable-unnecessary-system-services.md)**
    Disables unnecessary and high-risk system services to minimize the attack surface of standard client endpoints and member servers.

25. **[REQ-END-025 - Configure Secure Printing and Print Spooler Policies](configure-printing-and-spooler.md)**
    Configures printing security, RPC over TCP communication, Point and Print restrictions, and Redirection Guard, and disables incoming print spooler connections.

26. **[REQ-END-026 - Configure System Administrative Templates](configure-system-administrative-templates.md)**
    Enforces 91 administrative template settings including SMBv1 driver blocks, event log size extensions, and Windows Update scheduling.

27. **[REQ-END-027 - Configure AppLocker Policies](configure-applocker-policies.md)**
    Deploys AppLocker application control policies to restrict unauthorized software and script execution, and prevents default AppLocker bypasses.

28. **[REQ-END-028 - Configure Early Launch Antimalware (ELAM) Policy](configure-elam.md)**
    Configures the Early Launch Antimalware (ELAM) driver initialization policy to ensure only signed, trusted boot drivers execute.

29. **[REQ-END-029 - Configure Untrusted Font Blocking](configure-untrusted-font-blocking.md)**
    Configures the Untrusted Font Blocking mitigation to prevent loading of fonts outside the system fonts directory.

30. **[REQ-END-030 - Configure svchost.exe Mitigation Options](configure-svchost-mitigation.md)**
    Configures svchost.exe mitigation options on Tier 2 client workstations to restrict binary loading to Microsoft-signed code and block dynamic code execution.

31. **[REQ-END-031 - Enable Kernel-Mode Hardware-Enforced Stack Protection](enable-kernel-shadow-stacks.md)**
    Configures Kernel-mode Hardware-enforced Stack Protection to enforce hardware-backed control-flow integrity and mitigate kernel Return-Oriented Programming (ROP) execution hijacks.

32. **[REQ-END-032 - Disable Unused Windows Features and PowerShell 2.0 Engine](disable-unused-features.md)**
    Disables legacy, unused Windows optional features, including PowerShell 2.0, .NET Framework 3.5, and SMBv1 to minimize the client attack surface.

33. **[REQ-END-033 - Configure Microsoft Office Security and Block OLE Packages](configure-office-security.md)**
    Blocks VBA macros from running in Office files downloaded from the Internet, enforces macro digital signing warnings, and disables OLE Package execution in Outlook to prevent initial access exploits.

34. **[REQ-END-034 - Disable Windows Script Host and Remap Scripting Extensions](disable-windows-script-host.md)**
    Disables Windows Script Host execution globally and remaps standard scripting extensions (.vbs, .js, etc.) to open in Notepad by default to prevent execution by double-click.

35. **[REQ-END-035 - Configure Secure Boot Revocations and Bootloader Updates](configure-secure-boot-revocations.md)**
    Configures and enforces BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware.

36. **[REQ-END-036 - Enable WDAC Driver Blocklist](enable-wdac-driver-blocklist.md)**
    Enforces the Microsoft Vulnerable Driver Blocklist via Windows Defender Application Control (WDAC) to prevent known vulnerable or malicious drivers from loading in kernel space, mitigating Bring Your Own Vulnerable Driver (BYOVD) attacks.



