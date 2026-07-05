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
   * **[REQ-END-057 - Disable Real-Time Monitoring and Behavior Monitoring Override](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
   * **[REQ-END-058 - Configure Potentially Unwanted Applications (PUA) Protection](defender/configure-potentially-unwanted-applications-pua-protection.md)**
   * **[REQ-END-059 - Prevent Local List Merging and Exclusions Configuration](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
   * **[REQ-END-060 - Configure Auto Exclusions Configuration](defender/configure-auto-exclusions-configuration.md)**
   * **[REQ-END-061 - Prevent MAPS Local Setting Override](defender/prevent-maps-local-setting-override.md)**
   * **[REQ-END-062 - Enable EDR in Block Mode](defender/enable-edr-in-block-mode.md)**
   * **[REQ-END-063 - Allow Network Protection on Windows Server](defender/allow-network-protection-on-windows-server.md)**
   * **[REQ-END-064 - Enable File Hash Computation](defender/enable-file-hash-computation.md)**
   * **[REQ-END-065 - Configure Network Inspection System (NIS) settings](defender/configure-network-inspection-system-nis-settings.md)**
   * **[REQ-END-066 - Configure OOBE Real-Time Protection and Security Intelligence](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
   * **[REQ-END-067 - Enable Dynamic Signature Dropped Event Reporting](defender/enable-dynamic-signature-dropped-event-reporting.md)**
   * **[REQ-END-068 - Configure Quick Scan and Scanning Exclusions](defender/configure-quick-scan-and-scanning-exclusions.md)**
   * **[REQ-END-069 - Configure Scheduled Scan Parameters](defender/configure-scheduled-scan-parameters.md)**
   * **[REQ-END-070 - Configure Security Intelligence Update Schedule](defender/configure-security-intelligence-update-schedule.md)**
   * **[REQ-END-071 - Configure Attack Surface Reduction Rules](defender/configure-attack-surface-reduction-rules.md)**
      * **[REQ-END-080 - ASR: Block abuse of exploited vulnerable signed drivers](defender/asr/block-vulnerable-signed-drivers.md)**
      * **[REQ-END-081 - ASR: Block Adobe Reader from creating child processes](defender/asr/block-adobe-reader-child-processes.md)**
      * **[REQ-END-082 - ASR: Block all Office applications from creating child processes](defender/asr/block-office-child-processes.md)**
      * **[REQ-END-083 - ASR: Block credential stealing from the Windows local security authority subsystem](defender/asr/block-lsass-credential-stealing.md)**
      * **[REQ-END-084 - ASR: Block executable content from email client and webmail](defender/asr/block-email-executable-content.md)**
      * **[REQ-END-085 - ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion](defender/asr/block-low-prevalence-executable-files.md)**
      * **[REQ-END-086 - ASR: Block execution of potentially obfuscated scripts](defender/asr/block-obfuscated-scripts.md)**
      * **[REQ-END-087 - ASR: Block JavaScript or VBScript from launching downloaded executable content](defender/asr/block-script-launching-downloaded-content.md)**
      * **[REQ-END-088 - ASR: Block Office applications from creating executable content](defender/asr/block-office-executable-content-creation.md)**
      * **[REQ-END-089 - ASR: Block Office applications from injecting code into other processes](defender/asr/block-office-code-injection.md)**
      * **[REQ-END-090 - ASR: Block Office communication application from creating child processes](defender/asr/block-office-communication-child-processes.md)**
      * **[REQ-END-091 - ASR: Block persistence through WMI event subscription](defender/asr/block-wmi-event-subscription-persistence.md)**
      * **[REQ-END-092 - ASR: Block process creations originating from PSExec and WMI commands](defender/asr/block-psexec-wmi-process-creations.md)**
      * **[REQ-END-093 - ASR: Block untrusted and unsigned processes that run from USB](defender/asr/block-unsigned-processes-running-from-usb.md)**
      * **[REQ-END-094 - ASR: Block Win32 API calls from Office macros](defender/asr/block-win32-api-calls-from-office-macros.md)**
      * **[REQ-END-095 - ASR: Use advanced protection against ransomware](defender/asr/use-advanced-protection-against-ransomware.md)**
   * **[REQ-END-072 - Configure Threat Severity Default Quarantine Actions](defender/configure-threat-severity-default-quarantine-actions.md)**
   * **[REQ-END-073 - Configure Family Options UI Lockdown](defender/configure-family-options-ui-lockdown.md)**
   * **[REQ-END-074 - Configure Tamper Protection](defender/configure-tamper-protection.md)**
   * **[REQ-END-075 - Configure Sandbox Execution Environment](defender/configure-sandbox-execution-environment.md)**
   * **[REQ-END-076 - Configure AMSI Authenticode Signature Verification](defender/configure-amsi-authenticode-signature-verification.md)**
   * **[REQ-END-077 - Configure File Explorer SmartScreen](defender/configure-file-explorer-smartscreen.md)**
   * **[REQ-END-078 - Disable OneDrive File Sync](defender/disable-onedrive-file-sync.md)**
   * **[REQ-END-079 - Enforce Antivirus Scan on Opening Attachments](defender/enforce-antivirus-scan-on-opening-attachments.md)**

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
    * **[REQ-END-096 - Configure User Rights: Access Credential Manager as a trusted caller](user-rights/configure-ura-setrustedcredmanaccessprivilege.md)**
    * **[REQ-END-097 - Configure User Rights: Access this computer from the network](user-rights/configure-ura-senetworklogonright.md)**
    * **[REQ-END-098 - Configure User Rights: Act as part of the operating system](user-rights/configure-ura-setcbprivilege.md)**
    * **[REQ-END-099 - Configure User Rights: Allow log on locally](user-rights/configure-ura-seinteractivelogonright.md)**
    * **[REQ-END-100 - Configure User Rights: Back up files and directories](user-rights/configure-ura-sebackupprivilege.md)**
    * **[REQ-END-101 - Configure User Rights: Change the system time](user-rights/configure-ura-sesystemtimeprivilege.md)**
    * **[REQ-END-102 - Configure User Rights: Change the time zone](user-rights/configure-ura-setimezoneprivilege.md)**
    * **[REQ-END-103 - Configure User Rights: Create a pagefile](user-rights/configure-ura-secreatepagefileprivilege.md)**
    * **[REQ-END-104 - Configure User Rights: Create a token object](user-rights/configure-ura-secreatetokenprivilege.md)**
    * **[REQ-END-105 - Configure User Rights: Create global objects](user-rights/configure-ura-secreateglobalprivilege.md)**
    * **[REQ-END-106 - Configure User Rights: Create permanent shared objects](user-rights/configure-ura-secreatepermanentprivilege.md)**
    * **[REQ-END-107 - Configure User Rights: Create symbolic links](user-rights/configure-ura-secreatesymboliclinkprivilege.md)**
    * **[REQ-END-108 - Configure User Rights: Debug programs](user-rights/configure-ura-sedebugprivilege.md)**
    * **[REQ-END-109 - Configure User Rights: Enable computer and user accounts to be trusted for delegation](user-rights/configure-ura-seenabledelegationprivilege.md)**
    * **[REQ-END-110 - Configure User Rights: Force shutdown from a remote system](user-rights/configure-ura-seremoteshutdownprivilege.md)**
    * **[REQ-END-111 - Configure User Rights: Impersonate a client after authentication](user-rights/configure-ura-seimpersonateprivilege.md)**
    * **[REQ-END-112 - Configure User Rights: Increase scheduling priority](user-rights/configure-ura-seincreasebasepriorityprivilege.md)**
    * **[REQ-END-113 - Configure User Rights: Load and unload device drivers](user-rights/configure-ura-seloaddriverprivilege.md)**
    * **[REQ-END-114 - Configure User Rights: Lock pages in memory](user-rights/configure-ura-selockmemoryprivilege.md)**
    * **[REQ-END-115 - Configure User Rights: Manage auditing and security log](user-rights/configure-ura-sesecurityprivilege.md)**
    * **[REQ-END-116 - Configure User Rights: Modify firmware environment values](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
    * **[REQ-END-117 - Configure User Rights: Perform volume maintenance tasks](user-rights/configure-ura-semanagevolumeprivilege.md)**
    * **[REQ-END-118 - Configure User Rights: Profile single process](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
    * **[REQ-END-119 - Configure User Rights: Profile system performance](user-rights/configure-ura-sesystemprofileprivilege.md)**
    * **[REQ-END-120 - Configure User Rights: Replace a process level token](user-rights/configure-ura-seassignprimarytokenprivilege.md)**
    * **[REQ-END-121 - Configure User Rights: Restore files and directories](user-rights/configure-ura-serestoreprivilege.md)**
    * **[REQ-END-122 - Configure User Rights: Take ownership of files or other objects](user-rights/configure-ura-setakeownershipprivilege.md)**
    * **[REQ-END-123 - Configure User Rights: Modify an object label](user-rights/configure-ura-serelabelprivilege.md)**
    * **[REQ-END-124 - Configure User Rights: Deny access to this computer from the network](user-rights/configure-ura-sedenynetworklogonright.md)**
    * **[REQ-END-125 - Configure User Rights: Deny log on through Remote Desktop Services](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**

17. **[REQ-END-017 - Harden DMA and Physical Security](harden-dma-and-physical-security.md)**
    Mitigates physical access threat vectors by disabling standby sleep states (S1-S3), disabling external DMA device enumeration under lock, blocking legacy SBP-2 device classes, and denying write access to removable drives without BitLocker protection.

18. **[REQ-END-018 - Configure Account and Password Policies](configure-account-policies.md)**
    Enforces local and domain-wide account settings, including account lockout thresholds, lockout observation windows, smart card removal actions, and disabling reversible password encryption.

19. **[REQ-END-019 - Configure User Profile Restrictions](configure-user-profile-restrictions.md)**
    Locks down user profile registry settings (HKCU) to disable toast notifications on the lock screen and block third-party application suggestions.
    * **[REQ-END-126 - User Profile: Toast Notifications Lock Screen Restrictions](user-profile/configure-up-toast-notifications.md)**
    * **[REQ-END-127 - User Profile: Spotlight and Consumer Features Restrictions](user-profile/configure-up-spotlight-consumer.md)**
    * **[REQ-END-128 - User Profile: Windows Copilot Restrictions](user-profile/configure-up-windows-copilot.md)**
    * **[REQ-END-129 - User Profile: In-Place Sharing Restrictions](user-profile/configure-up-inplace-sharing.md)**
    * **[REQ-END-130 - User Profile: Shell RunAs User Suppression](user-profile/configure-up-runas-suppression.md)**
    * **[REQ-END-131 - User Profile: Personalization and Privacy Restrictions](user-profile/configure-up-personalization-privacy.md)**
    * **[REQ-END-132 - User Profile: Group Policy Processing Behaviors](user-profile/configure-up-gp-processing.md)**
    * **[REQ-END-133 - User Profile: Telemetry and Inventory Collection Restrictions](user-profile/configure-up-telemetry-inventory.md)**
    * **[REQ-END-134 - User Profile: Explorer Security and Memory Protections](user-profile/configure-up-explorer-security.md)**
    * **[REQ-END-135 - User Profile: Internet Explorer Options and Feeds Restrictions](user-profile/configure-up-ie-security.md)**
    * **[REQ-END-136 - User Profile: Interactive Logon Warning Banners](user-profile/configure-up-logon-banners.md)**
    * **[REQ-END-137 - User Profile: Interactive Logon Inactivity Timeout](user-profile/configure-up-inactivity-timeout.md)**
    * **[REQ-END-138 - User Profile: Windows Installer Hardening](user-profile/configure-up-installer-hardening.md)**
    * **[REQ-END-139 - User Profile: Secondary Logon Service Lockdown](user-profile/configure-up-seclogon-service.md)**
    * **[REQ-END-151 - User Profile: Structured Exception Handling Overwrite Protection (SEOP) for Endpoints](user-profile/configure-end-up-sehop.md)**
    * **[REQ-END-152 - User Profile: Directory Protection Mode for Endpoints](user-profile/configure-end-up-protection-mode.md)**
    * **[REQ-END-153 - User Profile: Address Space Layout Randomization (ASLR) Image Relocation for Endpoints](user-profile/configure-end-up-aslr-relocation.md)**
    * **[REQ-END-154 - User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for Endpoints](user-profile/configure-end-up-speculative-mitigations.md)**
    * **[REQ-END-155 - User Profile: Authenticode Certificate Padding Check for Endpoints](user-profile/configure-end-up-cert-padding.md)**
    * **[REQ-END-156 - User Profile: Command Processor Batch File Locking for Endpoints](user-profile/configure-end-up-lock-batch-files.md)**
    * **[REQ-END-157 - User Profile: Time-Travel Debugging (TTD) Recording Policy for Endpoints](user-profile/configure-end-up-ttd-recording.md)**
    * **[REQ-END-158 - User Profile: Trusted Root Store Protected Roots Certificate Restriction for Endpoints](user-profile/configure-end-up-protected-roots.md)**
    * **[REQ-END-159 - User Profile: Disabling Injection of AppInit DLLs for Endpoints](user-profile/configure-end-up-appinit-dlls.md)**
    * **[REQ-END-160 - User Profile: Preservation of Attachment Zone Information for Endpoints](user-profile/configure-end-up-attachment-zone.md)**
    * **[REQ-END-161 - User Profile: Disable Windows Game DVR for Endpoints](user-profile/configure-end-up-game-dvr.md)**
    * **[REQ-END-162 - User Profile: Restrict Windows Ink Workspace on Lock Screen for Endpoints](user-profile/configure-end-up-ink-workspace.md)**

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
    * **[REQ-END-037 - Disable Computer Browser Service (Browser)](services/disable-browser.md)**
    * **[REQ-END-038 - Disable Infrared Monitor Service (irmon)](services/disable-irmon.md)**
    * **[REQ-END-039 - Disable Internet Connection Sharing (ICS) Service (SharedAccess)](services/disable-sharedaccess.md)**
    * **[REQ-END-040 - Disable LxssManager Service (LxssManager)](services/disable-lxssmanager.md)**
    * **[REQ-END-041 - Disable Microsoft FTP Service (FTPSVC)](services/disable-ftpsvc.md)**
    * **[REQ-END-042 - Disable OpenSSH SSH Server Service (sshd)](services/disable-sshd.md)**
    * **[REQ-END-043 - Disable Remote Procedure Call (RPC) Locator Service (RpcLocator)](services/disable-rpclocator.md)**
    * **[REQ-END-044 - Disable Routing and Remote Access Service (RemoteAccess)](services/disable-remoteaccess.md)**
    * **[REQ-END-045 - Disable Simple TCP/IP Services (simptcp)](services/disable-simptcp.md)**
    * **[REQ-END-046 - Disable Special Administration Console Helper Service (sacsvr)](services/disable-sacsvr.md)**
    * **[REQ-END-047 - Disable SSDP Discovery Service (SSDPSRV)](services/disable-ssdpsrv.md)**
    * **[REQ-END-048 - Disable UPnP Device Host Service (upnphost)](services/disable-upnphost.md)**
    * **[REQ-END-049 - Disable Web Management Service (WMSvc)](services/disable-wmsvc.md)**
    * **[REQ-END-050 - Disable Windows Media Player Network Sharing Service (WMPNetworkSvc)](services/disable-wmpnetworksvc.md)**
    * **[REQ-END-051 - Disable Windows Mobile Hotspot Service (icssvc)](services/disable-icssvc.md)**
    * **[REQ-END-052 - Disable World Wide Web Publishing Service (W3SVC)](services/disable-w3svc.md)**
    * **[REQ-END-053 - Disable Xbox Accessory Management Service (XboxGipSvc)](services/disable-xboxgipsvc.md)**
    * **[REQ-END-054 - Disable Xbox Live Auth Manager Service (XblAuthManager)](services/disable-xblauthmanager.md)**
    * **[REQ-END-055 - Disable Xbox Live Game Save Service (XblGameSave)](services/disable-xblgamesave.md)**
    * **[REQ-END-056 - Disable Xbox Live Networking Service (XboxNetApiSvc)](services/disable-xboxnetapisvc.md)**

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

37. **[REQ-END-140 - Configure Advanced Security Audit Policies for Endpoints](audit-policy/README.md)**
    Enforces granular Windows security audit policies (including logons, group memberships, registry access, and system events) to log critical threat telemetry on Tier 2 client workstations.
    * **[REQ-END-141 - Audit Policy: Advanced Audit Policy Overrides for Endpoints](audit-policy/configure-end-audit-audit-override.md)**
    * **[REQ-END-142 - Audit Policy: Account Logon Auditing for Endpoints](audit-policy/configure-end-audit-account-logon.md)**
    * **[REQ-END-143 - Audit Policy: Account Management Auditing for Endpoints](audit-policy/configure-end-audit-account-management.md)**
    * **[REQ-END-144 - Audit Policy: Detailed Tracking Auditing for Endpoints](audit-policy/configure-end-audit-detailed-tracking.md)**
    * **[REQ-END-145 - Audit Policy: Logon and Logoff Auditing for Endpoints](audit-policy/configure-end-audit-logon-logoff.md)**
    * **[REQ-END-146 - Audit Policy: Object Access Auditing for Endpoints](audit-policy/configure-end-audit-object-access.md)**
    * **[REQ-END-147 - Audit Policy: Policy Change Auditing for Endpoints](audit-policy/configure-end-audit-policy-change.md)**
    * **[REQ-END-148 - Audit Policy: Privilege Use Auditing for Endpoints](audit-policy/configure-end-audit-privilege-use.md)**
    * **[REQ-END-149 - Audit Policy: System Events Auditing for Endpoints](audit-policy/configure-end-audit-system-events.md)**



