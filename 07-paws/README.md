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
   * **[REQ-PAW-057 - Disable Real-Time Monitoring and Behavior Monitoring Override for PAWs](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
   * **[REQ-PAW-058 - Configure Potentially Unwanted Applications (PUA) Protection for PAWs](defender/configure-potentially-unwanted-applications-pua-protection.md)**
   * **[REQ-PAW-059 - Prevent Local List Merging and Exclusions Configuration for PAWs](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
   * **[REQ-PAW-060 - Configure Auto Exclusions Configuration for PAWs](defender/configure-auto-exclusions-configuration.md)**
   * **[REQ-PAW-061 - Enable EDR in Block Mode for PAWs](defender/enable-edr-in-block-mode.md)**
   * **[REQ-PAW-062 - Allow Network Protection on Windows Server for PAWs](defender/allow-network-protection-on-windows-server.md)**
   * **[REQ-PAW-063 - Enable File Hash Computation for PAWs](defender/enable-file-hash-computation.md)**
   * **[REQ-PAW-064 - Configure Network Inspection System (NIS) settings for PAWs](defender/configure-network-inspection-system-nis-settings.md)**
   * **[REQ-PAW-065 - Configure OOBE Real-Time Protection and Security Intelligence for PAWs](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
   * **[REQ-PAW-066 - Enable Dynamic Signature Dropped Event Reporting for PAWs](defender/enable-dynamic-signature-dropped-event-reporting.md)**
   * **[REQ-PAW-067 - Configure Quick Scan and Scanning Exclusions for PAWs](defender/configure-quick-scan-and-scanning-exclusions.md)**
   * **[REQ-PAW-068 - Configure Scheduled Scan Parameters for PAWs](defender/configure-scheduled-scan-parameters.md)**
   * **[REQ-PAW-069 - Configure Security Intelligence Update Schedule for PAWs](defender/configure-security-intelligence-update-schedule.md)**
   * **[REQ-PAW-070 - Configure Attack Surface Reduction Rules for PAWs](defender/configure-attack-surface-reduction-rules.md)**
      * **[REQ-PAW-076 - ASR: Block abuse of exploited vulnerable signed drivers for PAWs](defender/asr/block-vulnerable-signed-drivers.md)**
      * **[REQ-PAW-077 - ASR: Block Adobe Reader from creating child processes for PAWs](defender/asr/block-adobe-reader-child-processes.md)**
      * **[REQ-PAW-078 - ASR: Block all Office applications from creating child processes for PAWs](defender/asr/block-office-child-processes.md)**
      * **[REQ-PAW-079 - ASR: Block credential stealing from the Windows local security authority subsystem for PAWs](defender/asr/block-lsass-credential-stealing.md)**
      * **[REQ-PAW-080 - ASR: Block executable content from email client and webmail for PAWs](defender/asr/block-email-executable-content.md)**
      * **[REQ-PAW-081 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion for PAWs](defender/asr/block-low-prevalence-executable-files.md)**
      * **[REQ-PAW-082 - ASR: Block execution of potentially obfuscated scripts for PAWs](defender/asr/block-obfuscated-scripts.md)**
      * **[REQ-PAW-083 - ASR: Block JavaScript or VBScript from launching downloaded executable content for PAWs](defender/asr/block-script-launching-downloaded-content.md)**
      * **[REQ-PAW-084 - ASR: Block Office applications from creating executable content for PAWs](defender/asr/block-office-executable-content-creation.md)**
      * **[REQ-PAW-085 - ASR: Block Office applications from injecting code into other processes for PAWs](defender/asr/block-office-code-injection.md)**
      * **[REQ-PAW-086 - ASR: Block Office communication application from creating child processes for PAWs](defender/asr/block-office-communication-child-processes.md)**
      * **[REQ-PAW-087 - ASR: Block persistence through WMI event subscription for PAWs](defender/asr/block-wmi-event-subscription-persistence.md)**
      * **[REQ-PAW-088 - ASR: Block process creations originating from PSExec and WMI commands for PAWs](defender/asr/block-psexec-wmi-process-creations.md)**
      * **[REQ-PAW-089 - ASR: Block untrusted and unsigned processes that run from USB for PAWs](defender/asr/block-unsigned-processes-running-from-usb.md)**
      * **[REQ-PAW-090 - ASR: Block Win32 API calls from Office macros for PAWs](defender/asr/block-win32-api-calls-from-office-macros.md)**
      * **[REQ-PAW-091 - ASR: Use advanced protection against ransomware for PAWs](defender/asr/use-advanced-protection-against-ransomware.md)**
   * **[REQ-PAW-071 - Configure Threat Severity Default Quarantine Actions for PAWs](defender/configure-threat-severity-default-quarantine-actions.md)**
   * **[REQ-PAW-072 - Configure Family Options UI Lockdown for PAWs](defender/configure-family-options-ui-lockdown.md)**
   * **[REQ-PAW-073 - Configure Tamper Protection for PAWs](defender/configure-tamper-protection.md)**
   * **[REQ-PAW-074 - Configure Sandbox Execution Environment for PAWs](defender/configure-sandbox-execution-environment.md)**
   * **[REQ-PAW-075 - Configure AMSI Authenticode Signature Verification for PAWs](defender/configure-amsi-authenticode-signature-verification.md)**

9. **[REQ-PAW-009 - Configure User Rights Assignments for PAWs](configure-user-rights-assignments.md)**
   Restricts critical user rights assignments (URAs) such as debugging programs, token impersonation, and denying network/interactive logon permissions for standard accounts on PAWs.
   * **[REQ-PAW-092 - Configure User Rights: Access Credential Manager as a trusted caller for PAWs](user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**
   * **[REQ-PAW-093 - Configure User Rights: Access this computer from the network for PAWs](user-rights/configure-ura-senetworklogonright.md)**
   * **[REQ-PAW-094 - Configure User Rights: Act as part of the operating system for PAWs](user-rights/configure-ura-setcbprivilege.md)**
   * **[REQ-PAW-095 - Configure User Rights: Allow log on locally for PAWs](user-rights/configure-ura-seinteractivelogonright.md)**
   * **[REQ-PAW-096 - Configure User Rights: Back up files and directories for PAWs](user-rights/configure-ura-sebackupprivilege.md)**
   * **[REQ-PAW-097 - Configure User Rights: Create a pagefile for PAWs](user-rights/configure-ura-secreatepagefileprivilege.md)**
   * **[REQ-PAW-098 - Configure User Rights: Create a token object for PAWs](user-rights/configure-ura-secreatetokenprivilege.md)**
   * **[REQ-PAW-099 - Configure User Rights: Create global objects for PAWs](user-rights/configure-ura-secreateglobalprivilege.md)**
   * **[REQ-PAW-100 - Configure User Rights: Create permanent shared objects for PAWs](user-rights/configure-ura-secreatepermanentprivilege.md)**
   * **[REQ-PAW-101 - Configure User Rights: Debug programs for PAWs](user-rights/configure-ura-sedebugprivilege.md)**
   * **[REQ-PAW-102 - Configure User Rights: Enable computer and user accounts to be trusted for delegation for PAWs](user-rights/configure-ura-seenabledelegationprivilege.md)**
   * **[REQ-PAW-103 - Configure User Rights: Force shutdown from a remote system for PAWs](user-rights/configure-ura-seremoteshutdownprivilege.md)**
   * **[REQ-PAW-104 - Configure User Rights: Impersonate a client after authentication for PAWs](user-rights/configure-ura-seimpersonateprivilege.md)**
   * **[REQ-PAW-105 - Configure User Rights: Load and unload device drivers for PAWs](user-rights/configure-ura-seloaddriverprivilege.md)**
   * **[REQ-PAW-106 - Configure User Rights: Lock pages in memory for PAWs](user-rights/configure-ura-selockmemoryprivilege.md)**
   * **[REQ-PAW-107 - Configure User Rights: Manage auditing and security log for PAWs](user-rights/configure-ura-sesecurityprivilege.md)**
   * **[REQ-PAW-108 - Configure User Rights: Modify firmware environment values for PAWs](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
   * **[REQ-PAW-109 - Configure User Rights: Perform volume maintenance tasks for PAWs](user-rights/configure-ura-semanagevolumeprivilege.md)**
   * **[REQ-PAW-110 - Configure User Rights: Profile single process for PAWs](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
   * **[REQ-PAW-111 - Configure User Rights: Restore files and directories for PAWs](user-rights/configure-ura-serestoreprivilege.md)**
   * **[REQ-PAW-112 - Configure User Rights: Take ownership of files or other objects for PAWs](user-rights/configure-ura-setakeownershipprivilege.md)**
   * **[REQ-PAW-113 - Configure User Rights: Deny access to this computer from the network for PAWs](user-rights/configure-ura-sedenynetworklogonright.md)**
   * **[REQ-PAW-114 - Configure User Rights: Deny log on through Remote Desktop Services for PAWs](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**

10. **[REQ-PAW-010 - Enable VBS and Credential Guard for PAWs](enable-vbs-credential-guard.md)**
    Configures Virtualization-Based Security (VBS), Credential Guard (with UEFI Lock), System Guard Secure Launch, and memory protections to shield LSASS from credential dumping attacks on PAWs.

11. **[REQ-PAW-011 - Harden DMA and Physical Security for PAWs](harden-dma-and-physical-security.md)**
    Mitigates physical access threat vectors by disabling sleep standby states (S1-S3), disabling external DMA device enumeration under lock, enforcing a strict block-all device enumeration policy, and blocking legacy SBP-2 device classes.

12. **[REQ-PAW-012 - Enable WDAC Driver Blocklist](enable-wdac-driver-blocklist.md)**
    Enforces the Microsoft Vulnerable Driver Blocklist using Windows Defender Application Control (WDAC) to protect the kernel from Bring Your Own Vulnerable Driver (BYOVD) attacks.

13. **[REQ-PAW-013 - Configure Account and Password Policies for PAWs](configure-account-policies.md)**
    Configures robust local account lockout, local password complexity, and 20-character minimum length policies, and references Active Directory Fine-Grained Password Policies (FGPP) for Tier 0 Administrators.
    * **[REQ-PAW-152 - Account Policy: Password Policy for PAWs](account-policy/configure-paw-account-password-policy.md)**
    * **[REQ-PAW-153 - Account Policy: Account Lockout Policy for PAWs](account-policy/configure-paw-account-lockout-policy.md)**
    * **[REQ-PAW-154 - Account Policy: Kerberos Policy for PAWs](account-policy/configure-paw-account-kerberos-policy.md)**
    * **[REQ-PAW-155 - Account Policy: Smart Card Removal Behavior for PAWs](account-policy/configure-paw-account-smart-card-removal.md)**
    * **[REQ-PAW-156 - Account Policy: Cached Logons and PBKDF2 Iteration Count for PAWs](account-policy/configure-paw-account-cached-logons.md)**
    * **[REQ-PAW-157 - Account Policy: Local Accounts and Blank Password Restrictions for PAWs](account-policy/configure-paw-account-local-blank-passwords.md)**
    * **[REQ-PAW-158 - Account Policy: NTLM and LAN Manager Authentication Security for PAWs](account-policy/configure-paw-account-ntlm-security.md)**
    * **[REQ-PAW-159 - Account Policy: Disable WDigest Credential Caching for PAWs](account-policy/configure-paw-account-wdigest-credentials.md)**
    * **[REQ-PAW-160 - Account Policy: Windows Hello for Business and PIN Complexity for PAWs](account-policy/configure-paw-account-hello-pin.md)**
    * **[REQ-PAW-161 - Account Policy: Consumer Microsoft Account Restrictions for PAWs](account-policy/configure-paw-account-block-msa.md)**
    * **[REQ-PAW-162 - Account Policy: Domain Member Secure Channel Security for PAWs](account-policy/configure-paw-account-secure-channel.md)**
    * **[REQ-PAW-163 - Account Policy: SMB Client and Server Security Options for PAWs](account-policy/configure-paw-account-smb-security.md)**
    * **[REQ-PAW-164 - Account Policy: Anonymous Access and Enumeration Restrictions for PAWs](account-policy/configure-paw-account-anonymous-restrictions.md)**
    * **[REQ-PAW-165 - Account Policy: Interactive Logon Security Options for PAWs](account-policy/configure-paw-account-interactive-logon.md)**

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
    * **[REQ-PAW-115 - User Profile: Toast Notifications Lock Screen Restrictions for PAWs](user-profile/configure-up-toast-notifications.md)**
    * **[REQ-PAW-116 - User Profile: Spotlight and Consumer Features Restrictions for PAWs](user-profile/configure-up-spotlight-consumer.md)**
    * **[REQ-PAW-117 - User Profile: Windows Copilot Restrictions for PAWs](user-profile/configure-up-windows-copilot.md)**
    * **[REQ-PAW-118 - User Profile: In-Place Sharing Restrictions for PAWs](user-profile/configure-up-inplace-sharing.md)**
    * **[REQ-PAW-119 - User Profile: Shell RunAs User Suppression for PAWs](user-profile/configure-up-runas-suppression.md)**
    * **[REQ-PAW-120 - User Profile: Personalization and Privacy Restrictions for PAWs](user-profile/configure-up-personalization-privacy.md)**
    * **[REQ-PAW-121 - User Profile: Group Policy Processing Behaviors for PAWs](user-profile/configure-up-gp-processing.md)**
    * **[REQ-PAW-122 - User Profile: Telemetry and Inventory Collection Restrictions for PAWs](user-profile/configure-up-telemetry-inventory.md)**
    * **[REQ-PAW-123 - User Profile: Explorer Security and Memory Protections for PAWs](user-profile/configure-up-explorer-security.md)**
    * **[REQ-PAW-124 - User Profile: Internet Explorer Options and Feeds Restrictions for PAWs](user-profile/configure-up-ie-security.md)**
    * **[REQ-PAW-125 - User Profile: Interactive Logon Warning Banners for PAWs](user-profile/configure-up-logon-banners.md)**
    * **[REQ-PAW-126 - User Profile: Interactive Logon Inactivity Timeout for PAWs](user-profile/configure-up-inactivity-timeout.md)**
    * **[REQ-PAW-127 - User Profile: Windows Installer Hardening for PAWs](user-profile/configure-up-installer-hardening.md)**
    * **[REQ-PAW-128 - User Profile: Secondary Logon Service Lockdown for PAWs](user-profile/configure-up-seclogon-service.md)**
    * **[REQ-PAW-140 - User Profile: Structured Exception Handling Overwrite Protection (SEOP) for PAWs](user-profile/configure-paw-up-sehop.md)**
    * **[REQ-PAW-141 - User Profile: Directory Protection Mode for PAWs](user-profile/configure-paw-up-protection-mode.md)**
    * **[REQ-PAW-142 - User Profile: Address Space Layout Randomization (ASLR) Image Relocation for PAWs](user-profile/configure-paw-up-aslr-relocation.md)**
    * **[REQ-PAW-143 - User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for PAWs](user-profile/configure-paw-up-speculative-mitigations.md)**
    * **[REQ-PAW-144 - User Profile: Authenticode Certificate Padding Check for PAWs](user-profile/configure-paw-up-cert-padding.md)**
    * **[REQ-PAW-145 - User Profile: Command Processor Batch File Locking for PAWs](user-profile/configure-paw-up-lock-batch-files.md)**
    * **[REQ-PAW-146 - User Profile: Time-Travel Debugging (TTD) Recording Policy for PAWs](user-profile/configure-paw-up-ttd-recording.md)**
    * **[REQ-PAW-147 - User Profile: Trusted Root Store Protected Roots Certificate Restriction for PAWs](user-profile/configure-paw-up-protected-roots.md)**
    * **[REQ-PAW-148 - User Profile: Disabling Injection of AppInit DLLs for PAWs](user-profile/configure-paw-up-appinit-dlls.md)**
    * **[REQ-PAW-149 - User Profile: Preservation of Attachment Zone Information for PAWs](user-profile/configure-paw-up-attachment-zone.md)**
    * **[REQ-PAW-150 - User Profile: Disable Windows Game DVR for PAWs](user-profile/configure-paw-up-game-dvr.md)**
    * **[REQ-PAW-151 - User Profile: Restrict Windows Ink Workspace on Lock Screen for PAWs](user-profile/configure-paw-up-ink-workspace.md)**

25. **[REQ-PAW-025 - Configure Exploit Protection Profile for PAWs](configure-exploit-protection.md)**
    Configures and enforces a system-wide Microsoft Defender Exploit Protection profile to apply advanced memory mitigations (DEP, ASLR, CFG, SEHOP, Heap Integrity) on all PAWs.

26. **[REQ-PAW-026 - Restrict Safe Mode Access to Administrators on PAWs](disable-safe-mode-for-standard-users.md)**
    Prevents standard (non-administrative) users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

27. **[REQ-PAW-027 - Configure Windows Defender Firewall and Block LOLBins for PAWs](configure-windows-firewall.md)**
    Configures host firewall profiles and outbound rules to block known Living Off the Land Binaries (LOLBins) from initiating outgoing network connections.

28. **[REQ-PAW-028 - Disable Unnecessary System Services for PAWs](disable-unnecessary-system-services.md)**
    Disables unnecessary and high-risk system services to minimize the attack surface of administrative endpoints.
    * **[REQ-PAW-037 - Disable Computer Browser Service for PAWs (Browser)](services/disable-browser.md)**
    * **[REQ-PAW-038 - Disable Infrared Monitor Service for PAWs (irmon)](services/disable-irmon.md)**
    * **[REQ-PAW-039 - Disable Internet Connection Sharing (ICS) Service for PAWs (SharedAccess)](services/disable-sharedaccess.md)**
    * **[REQ-PAW-040 - Disable LxssManager Service for PAWs (LxssManager)](services/disable-lxssmanager.md)**
    * **[REQ-PAW-041 - Disable Microsoft FTP Service for PAWs (FTPSVC)](services/disable-ftpsvc.md)**
    * **[REQ-PAW-042 - Disable OpenSSH SSH Server Service for PAWs (sshd)](services/disable-sshd.md)**
    * **[REQ-PAW-043 - Disable Remote Procedure Call (RPC) Locator Service for PAWs (RpcLocator)](services/disable-rpclocator.md)**
    * **[REQ-PAW-044 - Disable Routing and Remote Access Service for PAWs (RemoteAccess)](services/disable-remoteaccess.md)**
    * **[REQ-PAW-045 - Disable Simple TCP/IP Services for PAWs (simptcp)](services/disable-simptcp.md)**
    * **[REQ-PAW-046 - Disable Special Administration Console Helper Service for PAWs (sacsvr)](services/disable-sacsvr.md)**
    * **[REQ-PAW-047 - Disable SSDP Discovery Service for PAWs (SSDPSRV)](services/disable-ssdpsrv.md)**
    * **[REQ-PAW-048 - Disable UPnP Device Host Service for PAWs (upnphost)](services/disable-upnphost.md)**
    * **[REQ-PAW-049 - Disable Web Management Service for PAWs (WMSvc)](services/disable-wmsvc.md)**
    * **[REQ-PAW-050 - Disable Windows Media Player Network Sharing Service for PAWs (WMPNetworkSvc)](services/disable-wmpnetworksvc.md)**
    * **[REQ-PAW-051 - Disable Windows Mobile Hotspot Service for PAWs (icssvc)](services/disable-icssvc.md)**
    * **[REQ-PAW-052 - Disable World Wide Web Publishing Service for PAWs (W3SVC)](services/disable-w3svc.md)**
    * **[REQ-PAW-053 - Disable Xbox Accessory Management Service for PAWs (XboxGipSvc)](services/disable-xboxgipsvc.md)**
    * **[REQ-PAW-054 - Disable Xbox Live Auth Manager Service for PAWs (XblAuthManager)](services/disable-xblauthmanager.md)**
    * **[REQ-PAW-055 - Disable Xbox Live Game Save Service for PAWs (XblGameSave)](services/disable-xblgamesave.md)**
    * **[REQ-PAW-056 - Disable Xbox Live Networking Service for PAWs (XboxNetApiSvc)](services/disable-xboxnetapisvc.md)**
    * **[REQ-PAW-166 - Disable WebClient Service for PAWs (WebClient)](services/disable-webclient.md)**

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

36. **[REQ-PAW-036 - Configure Windows Defender Application Control](configure-wdac.md)**
    Deploys Windows Defender Application Control (WDAC) on PAWs in Audit Mode to block unauthorized system-level binaries and scripts.

37. **[REQ-PAW-129 - Configure Advanced Security Audit Policies for PAWs](audit-policy/README.md)**
    Enforces granular Windows security audit policies (including logons, group memberships, registry access, and system events) to log critical threat telemetry on privileged access workstations.
    * **[REQ-PAW-130 - Audit Policy: Advanced Audit Policy Overrides for PAWs](audit-policy/configure-paw-audit-audit-override.md)**
    * **[REQ-PAW-131 - Audit Policy: Account Logon Auditing for PAWs](audit-policy/configure-paw-audit-account-logon.md)**
    * **[REQ-PAW-132 - Audit Policy: Account Management Auditing for PAWs](audit-policy/configure-paw-audit-account-management.md)**
    * **[REQ-PAW-133 - Audit Policy: Detailed Tracking Auditing for PAWs](audit-policy/configure-paw-audit-detailed-tracking.md)**
    * **[REQ-PAW-134 - Audit Policy: Logon and Logoff Auditing for PAWs](audit-policy/configure-paw-audit-logon-logoff.md)**
    * **[REQ-PAW-135 - Audit Policy: Object Access Auditing for PAWs](audit-policy/configure-paw-audit-object-access.md)**
    * **[REQ-PAW-136 - Audit Policy: Policy Change Auditing for PAWs](audit-policy/configure-paw-audit-policy-change.md)**
    * **[REQ-PAW-137 - Audit Policy: Privilege Use Auditing for PAWs](audit-policy/configure-paw-audit-privilege-use.md)**
    * **[REQ-PAW-138 - Audit Policy: System Events Auditing for PAWs](audit-policy/configure-paw-audit-system-events.md)**




