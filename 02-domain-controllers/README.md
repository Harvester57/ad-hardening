# Module 2: Domain Controller Hardening

This directory contains security baselines for Domain Controllers running Windows Server 2016 and above in high-security, air-gapped Active Directory environments.

## Technical Hardening Controls

* **[REQ-DC-001 - Disable SMBv1](disable-smbv1.md)**
  Requirement to disable the legacy SMBv1 protocol and its associated client-side driver to prevent remote code execution and spoofing vulnerabilities.
* **[REQ-DC-002 - Disable Multicast Name Resolution](disable-multicast-name-resolution.md)**
  Requirement to disable LLMNR, NetBIOS (NBT-NS), and mDNS to prevent local name resolution spoofing and credential harvesting.
* **[REQ-DC-003 - Disable NTLMv1](disable-ntlmv1.md)**
  Requirement to restrict NTLM authentication to NTLMv2 or Kerberos to protect credentials from offline brute-force cracking.
* **[REQ-DC-004 - Enforce LDAP Server Signing](enforce-ldap-signing.md)**
  Requirement to enforce packet signing on LDAP cleartext traffic to protect directory transactions from man-in-the-middle attacks.
* **[REQ-DC-005 - Enforce LDAP Channel Binding](enforce-ldap-channel-binding.md)**
  Requirement to enforce LDAP Channel Binding Tokens (CBT) over secure LDAPS connections to prevent authentication relay attacks.
* **[REQ-DC-006 - Enable LSA Protection](enable-lsa-protection.md)**
  Requirement to configure the Local Security Authority (LSA) process to run as a Protected Process Light (PPL) to protect credential secrets from LSASS memory dumps.
* **[REQ-DC-007 - Disable Credential Guard](disable-credential-guard.md)**
  Requirement to disable Windows Defender Credential Guard on Domain Controllers in accordance with Microsoft recommendations while keeping Virtualization-Based Security (VBS) enabled.
* **[REQ-DC-008 - Disable Print Spooler Service](disable-print-spooler.md)**
  Requirement to stop and disable the Print Spooler service on Domain Controllers to prevent remote execution and coercive authentication attacks.
* **[REQ-DC-009 - Enforce SMB Message Signing](enforce-smb-signing.md)**
  Requirement to enforce SMB client and server signing to protect file transfer data and block SMB relay attacks.
* **[REQ-DC-010 - Restrict Kerberos Encryption Types](restrict-kerberos-encryption.md)**
  Requirement to configure allowed Kerberos encryption types, restricting to AES128/AES256 and disabling legacy DES and RC4 to prevent Kerberoasting.
* **[REQ-DC-011 - Restrict Remote SAM API Access](restrict-ntds-sam-api.md)**
  Requirement to restrict remote RPC access to the SAM database to local Administrators, preventing remote recon and user enumeration.
* **[REQ-DC-012 - Disable Unnecessary Services on Domain Controllers](disable-unnecessary-services.md)**
  Requirement to disable unnecessary system services (such as Xbox services and other non-essential services) on Domain Controllers to minimize the attack surface.
  * **[REQ-DC-035 - Disable Xbox Live Auth Manager (XblAuthManager)](services/disable-xblauthmanager.md)**
  * **[REQ-DC-036 - Disable Xbox Live Game Save (XblGameSave)](services/disable-xblgamesave.md)**
  * **[REQ-DC-037 - Disable ActiveX Installer (AxInstSV)](services/disable-axinstsv.md)**
  * **[REQ-DC-038 - Disable Bluetooth Support Service (bthserv)](services/disable-bthserv.md)**
  * **[REQ-DC-039 - Disable Connected Devices Platform User Service (CDPUserSvc)](services/disable-cdpusersvc.md)**
  * **[REQ-DC-040 - Disable Contact Data (PimIndexMaintenanceSvc)](services/disable-pimindexmaintenancesvc.md)**
  * **[REQ-DC-041 - Disable WAP Push Message Routing Service (dmwappushservice)](services/disable-dmwappushservice.md)**
  * **[REQ-DC-042 - Disable Downloaded Maps Manager (MapsBroker)](services/disable-mapsbroker.md)**
  * **[REQ-DC-043 - Disable Geolocation Service (lfsvc)](services/disable-lfsvc.md)**
  * **[REQ-DC-044 - Disable Internet Connection Sharing (ICS) (SharedAccess)](services/disable-sharedaccess.md)**
  * **[REQ-DC-045 - Disable Link-Layer Topology Discovery Mapper (lltdsvc)](services/disable-lltdsvc.md)**
  * **[REQ-DC-046 - Disable Microsoft Account Sign-in Assistant (wlidsvc)](services/disable-wlidsvc.md)**
  * **[REQ-DC-047 - Disable Microsoft Passport (NgcSvc)](services/disable-ngcsvc.md)**
  * **[REQ-DC-048 - Disable Microsoft Passport Container (NgcCtnrSvc)](services/disable-ngcctnrsvc.md)**
  * **[REQ-DC-049 - Disable Network Connection Broker (NcbService)](services/disable-ncbservice.md)**
  * **[REQ-DC-050 - Disable Phone Service (PhoneSvc)](services/disable-phonesvc.md)**
  * **[REQ-DC-051 - Disable Printer Extensions and Notifications (PrintNotify)](services/disable-printnotify.md)**
  * **[REQ-DC-052 - Disable Program Compatibility Assistant Service (PcaSvc)](services/disable-pcasvc.md)**
  * **[REQ-DC-053 - Disable Quality Windows Audio Video Experience (QWAVE)](services/disable-qwave.md)**
  * **[REQ-DC-054 - Disable Radio Management Service (RmSvc)](services/disable-rmsvc.md)**
  * **[REQ-DC-055 - Disable Sensor Data Service (SensorDataService)](services/disable-sensordataservice.md)**
  * **[REQ-DC-056 - Disable Sensor Monitoring Service (SensrSvc)](services/disable-sensrsvc.md)**
  * **[REQ-DC-057 - Disable Sensor Service (SensorService)](services/disable-sensorservice.md)**
  * **[REQ-DC-058 - Disable Shell Hardware Detection (ShellHWDetection)](services/disable-shellhwdetection.md)**
  * **[REQ-DC-059 - Disable Smart Card Device Enumeration Service (ScDeviceEnum)](services/disable-scdeviceenum.md)**
  * **[REQ-DC-060 - Disable SSDP Discovery (SSDPSRV)](services/disable-ssdpsrv.md)**
  * **[REQ-DC-061 - Disable Still Image Acquisition Events (WiaRpc)](services/disable-wiarpc.md)**
  * **[REQ-DC-062 - Disable Sync Host (OneSyncSvc)](services/disable-onesyncsvc.md)**
  * **[REQ-DC-063 - Disable UPnP Device Host (upnphost)](services/disable-upnphost.md)**
  * **[REQ-DC-064 - Disable User Data Access (UserDataSvc)](services/disable-userdatasvc.md)**
  * **[REQ-DC-065 - Disable User Data Storage (UnistoreSvc)](services/disable-unistoresvc.md)**
  * **[REQ-DC-066 - Disable WalletService (WalletService)](services/disable-walletservice.md)**
  * **[REQ-DC-067 - Disable Windows Audio (Audiosrv)](services/disable-audiosrv.md)**
  * **[REQ-DC-068 - Disable Windows Audio Endpoint Builder (AudioEndpointBuilder)](services/disable-audioendpointbuilder.md)**
  * **[REQ-DC-069 - Disable Windows Camera Frame Server (FrameServer)](services/disable-frameserver.md)**
  * **[REQ-DC-070 - Disable Windows Image Acquisition (WIA) (stisvc)](services/disable-stisvc.md)**
  * **[REQ-DC-071 - Disable Windows Insider Service (wisvc)](services/disable-wisvc.md)**
  * **[REQ-DC-072 - Disable Windows Mobile Hotspot Service (icssvc)](services/disable-icssvc.md)**
  * **[REQ-DC-073 - Disable Windows Push Notifications System Service (WpnService)](services/disable-wpnservice.md)**
  * **[REQ-DC-074 - Disable Windows Push Notifications User Service (WpnUserService)](services/disable-wpnuserservice.md)**
* **[REQ-DC-013 - Enable Kerberos Armoring](enable-kerberos-armoring.md)**
  Requirement to enable Kerberos Armoring (FAST) on Domain Controllers and client endpoints to encrypt pre-authentication exchanges and protect credentials from offline brute-force attacks.
* **[REQ-DC-014 - Restrict NTLM](restrict-ntlm.md)**
  Requirement to audit and restrict NTLMv2 and domain-wide NTLM authentication to prevent credential relaying and force the transition to Kerberos.
* **[REQ-DC-015 - Migrate SYSVOL Replication to DFSR](migrate-sysvol-replication-dfsr.md)**
  Requirement to migrate SYSVOL folder replication from legacy FRS to secure DFSR to ensure replication integrity and disable deprecated services.
* **[REQ-DC-016 - Harden adminSDHolder Permissions](harden-adminsdholder-permissions.md)**
  Requirement to secure the adminSDHolder object's Access Control List to prevent privilege escalation backdoors on protected accounts.
* **[REQ-DC-017 - Harden Microsoft DNS AD Container Permissions](harden-dns-container-permissions.md)**
  Requirement to secure CN=MicrosoftDNS,CN=System container permissions and block DNS service DLL hijacking (ServerLevelPluginDll).
* **[REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](harden-dc-virtualization-hosts.md)**
  Requirement to treat virtualization hypervisors hosting Domain Controllers as Tier 0 systems, separating host hardware and enforcing VM encryption.
* **[REQ-DC-019 - Enforce RDP Restricted Admin Mode](enforce-rdp-restricted-admin.md)**
  Requirement to configure and require RDP Restricted Admin Mode on administrative clients and servers to protect credentials in host memory.
* **[REQ-DC-020 - Windows Defender Antivirus Domain Controller Baseline and Exploit Guard](defender-antivirus.md)**
  Requirement to configure and harden Windows Defender Antivirus on Domain Controllers, enabling real-time scanning, preventing local exclusion modifications, enforcing server-compatible ASR rules (including LSASS protection), activating Tamper Protection, and sandboxing execution.
  * **[REQ-DC-075 - Disable Real-Time Monitoring and Behavior Monitoring Override on Domain Controllers](defender/disable-real-time-monitoring-and-behavior-monitoring-override.md)**
  * **[REQ-DC-076 - Configure Potentially Unwanted Applications (PUA) Protection on Domain Controllers](defender/configure-potentially-unwanted-applications-pua-protection.md)**
  * **[REQ-DC-077 - Prevent Local List Merging and Exclusions Configuration on Domain Controllers](defender/prevent-local-list-merging-and-exclusions-configuration.md)**
  * **[REQ-DC-078 - Configure Auto Exclusions Configuration on Domain Controllers](defender/configure-auto-exclusions-configuration.md)**
  * **[REQ-DC-079 - Prevent MAPS Local Setting Override on Domain Controllers](defender/prevent-maps-local-setting-override.md)**
  * **[REQ-DC-080 - Enable EDR in Block Mode on Domain Controllers](defender/enable-edr-in-block-mode.md)**
  * **[REQ-DC-081 - Allow Network Protection on Windows Server on Domain Controllers](defender/allow-network-protection-on-windows-server.md)**
  * **[REQ-DC-082 - Enable File Hash Computation on Domain Controllers](defender/enable-file-hash-computation.md)**
  * **[REQ-DC-083 - Configure Network Inspection System (NIS) settings on Domain Controllers](defender/configure-network-inspection-system-nis-settings.md)**
  * **[REQ-DC-084 - Configure OOBE Real-Time Protection and Security Intelligence on Domain Controllers](defender/configure-oobe-real-time-protection-and-security-intelligence.md)**
  * **[REQ-DC-085 - Enable Dynamic Signature Dropped Event Reporting on Domain Controllers](defender/enable-dynamic-signature-dropped-event-reporting.md)**
  * **[REQ-DC-086 - Disable Generic Reports on Domain Controllers](defender/disable-generic-reports.md)**
  * **[REQ-DC-087 - Configure Behavioral Network Brute Force Protection Aggressiveness on Domain Controllers](defender/configure-brute-force-protection.md)**
  * **[REQ-DC-088 - Configure Behavioral Network Remote Encryption Protection Aggressiveness on Domain Controllers](defender/configure-remote-encryption-protection.md)**
  * **[REQ-DC-089 - Configure Quick Scan and Scanning Exclusions on Domain Controllers](defender/configure-quick-scan-and-scanning-exclusions.md)**
  * **[REQ-DC-090 - Configure Scheduled Scan Parameters on Domain Controllers](defender/configure-scheduled-scan-parameters.md)**
  * **[REQ-DC-091 - Configure Security Intelligence Update Schedule on Domain Controllers](defender/configure-security-intelligence-update-schedule.md)**
  * **[REQ-DC-092 - Configure Attack Surface Reduction Rules on Domain Controllers](defender/configure-attack-surface-reduction-rules.md)**
    * **[REQ-DC-098 - ASR: Block abuse of exploited vulnerable signed drivers on Domain Controllers](defender/asr/block-vulnerable-signed-drivers.md)**
    * **[REQ-DC-099 - ASR: Block credential stealing from the Windows local security authority subsystem on Domain Controllers](defender/asr/block-lsass-credential-stealing.md)**
    * **[REQ-DC-100 - ASR: Block execution of potentially obfuscated scripts on Domain Controllers](defender/asr/block-obfuscated-scripts.md)**
    * **[REQ-DC-101 - ASR: Block persistence through WMI event subscription on Domain Controllers](defender/asr/block-wmi-event-subscription-persistence.md)**
    * **[REQ-DC-102 - ASR: Block process creations originating from PSExec and WMI commands on Domain Controllers](defender/asr/block-psexec-wmi-process-creations.md)**
    * **[REQ-DC-103 - ASR: Use advanced protection against ransomware on Domain Controllers](defender/asr/use-advanced-protection-against-ransomware.md)**
  * **[REQ-DC-093 - Configure Threat Severity Default Quarantine Actions on Domain Controllers](defender/configure-threat-severity-default-quarantine-actions.md)**
  * **[REQ-DC-094 - Configure Family Options UI Lockdown on Domain Controllers](defender/configure-family-options-ui-lockdown.md)**
  * **[REQ-DC-095 - Configure Tamper Protection on Domain Controllers](defender/configure-tamper-protection.md)**
  * **[REQ-DC-096 - Configure Sandbox Execution Environment on Domain Controllers](defender/configure-sandbox-execution-environment.md)**
  * **[REQ-DC-097 - Configure AMSI Authenticode Signature Verification on Domain Controllers](defender/configure-amsi-authenticode-signature-verification.md)**
* **[REQ-DC-021 - Configure AppLocker Policies on Domain Controllers](configure-applocker-policies.md)**
  Requirement to configure strict AppLocker rules on Domain Controllers to prevent administrative users from executing unapproved binaries, scripts, installers, or web browsers on Tier 0 systems.
* **[REQ-DC-022 - Enable WDAC Driver Blocklist](enable-wdac-driver-blocklist.md)**
  Requirement to configure the Windows Defender Application Control (WDAC) driver blocklist to protect kernel memory from Bring Your Own Vulnerable Driver (BYOVD) attacks.
* **[REQ-DC-023 - Configure User Rights Assignments for Domain Controllers](configure-user-rights-assignments.md)**
  Requirement to restrict local user rights assignments on Domain Controllers to prevent default operator groups (Print Operators, Server Operators, Backup Operators) from logging on locally, backing up/restoring files, or shutting down Domain Controllers.
  * **[REQ-DC-104 - Configure User Rights: Access this computer from the network on Domain Controllers](user-rights/configure-ura-senetworklogonright.md)**
  * **[REQ-DC-105 - Configure User Rights: Act as part of the operating system on Domain Controllers](user-rights/configure-ura-setcbprivilege.md)**
  * **[REQ-DC-106 - Configure User Rights: Add workstations to domain on Domain Controllers](user-rights/configure-ura-semachineaccountprivilege.md)**
  * **[REQ-DC-107 - Configure User Rights: Adjust memory quotas for a process on Domain Controllers](user-rights/configure-ura-seincreasequotaprivilege.md)**
  * **[REQ-DC-108 - Configure User Rights: Allow log on locally on Domain Controllers](user-rights/configure-ura-seinteractivelogonright.md)**
  * **[REQ-DC-109 - Configure User Rights: Allow log on through Remote Desktop Services on Domain Controllers](user-rights/configure-ura-seremoteinteractivelogonright.md)**
  * **[REQ-DC-110 - Configure User Rights: Back up files and directories on Domain Controllers](user-rights/configure-ura-sebackupprivilege.md)**
  * **[REQ-DC-111 - Configure User Rights: Bypass traverse checking on Domain Controllers](user-rights/configure-ura-sechangenotifyprivilege.md)**
  * **[REQ-DC-112 - Configure User Rights: Change the system time on Domain Controllers](user-rights/configure-ura-sesystemtimeprivilege.md)**
  * **[REQ-DC-113 - Configure User Rights: Create a pagefile on Domain Controllers](user-rights/configure-ura-secreatepagefileprivilege.md)**
  * **[REQ-DC-114 - Configure User Rights: Create a token object on Domain Controllers](user-rights/configure-ura-secreatetokenprivilege.md)**
  * **[REQ-DC-115 - Configure User Rights: Create permanent shared objects on Domain Controllers](user-rights/configure-ura-secreatepermanentprivilege.md)**
  * **[REQ-DC-116 - Configure User Rights: Debug programs on Domain Controllers](user-rights/configure-ura-sedebugprivilege.md)**
  * **[REQ-DC-117 - Configure User Rights: Deny access to this computer from the network on Domain Controllers](user-rights/configure-ura-sedenynetworklogonright.md)**
  * **[REQ-DC-118 - Configure User Rights: Deny log on as a batch job on Domain Controllers](user-rights/configure-ura-sedenybatchlogonright.md)**
  * **[REQ-DC-119 - Configure User Rights: Deny log on as a service on Domain Controllers](user-rights/configure-ura-sedenyservicelogonright.md)**
  * **[REQ-DC-120 - Configure User Rights: Deny log on locally on Domain Controllers](user-rights/configure-ura-sedenyinteractivelogonright.md)**
  * **[REQ-DC-121 - Configure User Rights: Deny log on through Remote Desktop Services on Domain Controllers](user-rights/configure-ura-sedenyremoteinteractivelogonright.md)**
  * **[REQ-DC-122 - Configure User Rights: Enable computer and user accounts to be trusted for delegation on Domain Controllers](user-rights/configure-ura-seenabledelegationprivilege.md)**
  * **[REQ-DC-123 - Configure User Rights: Force shutdown from a remote system on Domain Controllers](user-rights/configure-ura-seremoteshutdownprivilege.md)**
  * **[REQ-DC-124 - Configure User Rights: Generate security audits on Domain Controllers](user-rights/configure-ura-seauditprivilege.md)**
  * **[REQ-DC-125 - Configure User Rights: Load and unload device drivers on Domain Controllers](user-rights/configure-ura-seloaddriverprivilege.md)**
  * **[REQ-DC-126 - Configure User Rights: Lock pages in memory on Domain Controllers](user-rights/configure-ura-selockmemoryprivilege.md)**
  * **[REQ-DC-127 - Configure User Rights: Log on as a batch job on Domain Controllers](user-rights/configure-ura-sebatchlogonright.md)**
  * **[REQ-DC-128 - Configure User Rights: Log on as a service on Domain Controllers](user-rights/configure-ura-seservicelogonright.md)**
  * **[REQ-DC-129 - Configure User Rights: Manage auditing and security log on Domain Controllers](user-rights/configure-ura-sesecurityprivilege.md)**
  * **[REQ-DC-130 - Configure User Rights: Modify firmware environment values on Domain Controllers](user-rights/configure-ura-sesystemenvironmentprivilege.md)**
  * **[REQ-DC-131 - Configure User Rights: Profile single process on Domain Controllers](user-rights/configure-ura-seprofilesingleprocessprivilege.md)**
  * **[REQ-DC-132 - Configure User Rights: Restore files and directories on Domain Controllers](user-rights/configure-ura-serestoreprivilege.md)**
  * **[REQ-DC-133 - Configure User Rights: Shut down the system on Domain Controllers](user-rights/configure-ura-seshutdownprivilege.md)**
  * **[REQ-DC-134 - Configure User Rights: Synchronize directory service data on Domain Controllers](user-rights/configure-ura-sesyncagentprivilege.md)**
  * **[REQ-DC-135 - Configure User Rights: Take ownership of files or other objects on Domain Controllers](user-rights/configure-ura-setakeownershipprivilege.md)**
* **[REQ-DC-024 - Configure dSHeuristics](configure-dsheuristics.md)**
  Requirement to audit and configure the dSHeuristics forest-wide attribute to reach maximum Level 5 security, blocking anonymous LDAP and NSPI operations, securing adminSDHolder, and enforcing KB5008383 owner implicit rights protections.
* **[REQ-DC-025 - Configure Security Options for Domain Controllers](configure-security-options.md)**
  Requirement to configure baseline administrative template Security Options, disabling anonymous access to SAM/shares and enforcing credential policies.
* **[REQ-DC-026 - Configure TCP/IP and Network Parameter Hardening for Domain Controllers](harden-network-parameters.md)**
  Requirement to configure hardened network configurations, TCP/IP MSS parameters, disabling LLTDIO/RSPNDR drivers, Peer-to-Peer, and Windows Connect Now.
* **[REQ-DC-027 - Configure Telemetry, Diagnostics and Privacy Options for Domain Controllers](configure-telemetry-privacy.md)**
  Requirement to restrict telemetry collection, online diagnostics, advertising IDs, diagnostic tools, and cloud content integration.
* **[REQ-DC-028 - Configure Untrusted Font Blocking for Domain Controllers](configure-untrusted-font-blocking.md)**
  Requirement to configure the Untrusted Font Blocking mitigation on Domain Controllers to prevent kernel font parser exploits.
* **[REQ-DC-029 - Configure svchost.exe Mitigation Options](configure-svchost-mitigation.md)**
  Requirement to configure svchost.exe mitigation options on Domain Controllers and Member Servers to restrict binary loading to Microsoft-signed code and block dynamic code execution.
* **[REQ-DC-030 - Secure Directory Services Restore Mode (DSRM) and Recovery Parameters](harden-dsrm-recovery-mode.md)**
  Requirement to secure DSRM restore mode logon behavior and recovery credentials parameters.
* **[REQ-DC-031 - Configure NTP Time Synchronization on the PDC Emulator](configure-pdc-time-sync.md)**
  Requirement to configure NTP time synchronization on the PDC Emulator to serve as a reliable time source and secure Kerberos exchanges.
* **[REQ-DC-032 - Enable UEFI Secure Boot](enable-secure-boot.md)**
  Requirement to enforce hardware-rooted platform integrity checks, verifying that UEFI Secure Boot is active on Domain Controllers.
* **[REQ-DC-033 - Configure Secure Boot Revocations and Bootloader Updates](configure-secure-boot-revocations.md)**
  Requirement to configure and enforce BlackLotus revocation updates and bootloader integrity verification policy variables in system firmware.
* **[REQ-DC-034 - Configure Windows Defender Application Control](configure-wdac.md)**
  Requirement to deploy Windows Defender Application Control (WDAC) on Domain Controllers in Audit Mode to block unauthorized system-level binaries and scripts.
* **[REQ-DC-136 - Audit Policy: Advanced Audit Policy Overrides](audit-policy/configure-dc-audit-audit-override.md)**
* **[REQ-DC-137 - Audit Policy: Account Logon Auditing](audit-policy/configure-dc-audit-account-logon.md)**
* **[REQ-DC-138 - Audit Policy: Account Management Auditing](audit-policy/configure-dc-audit-account-management.md)**
* **[REQ-DC-139 - Audit Policy: Detailed Tracking Auditing](audit-policy/configure-dc-audit-detailed-tracking.md)**
* **[REQ-DC-140 - Audit Policy: Directory Service Access Auditing](audit-policy/configure-dc-audit-ds-access.md)**
* **[REQ-DC-141 - Audit Policy: Logon and Logoff Auditing](audit-policy/configure-dc-audit-logon-logoff.md)**
* **[REQ-DC-142 - Audit Policy: Object Access Auditing](audit-policy/configure-dc-audit-object-access.md)**
* **[REQ-DC-143 - Audit Policy: Policy Change Auditing](audit-policy/configure-dc-audit-policy-change.md)**
* **[REQ-DC-144 - Audit Policy: Privilege Use Auditing](audit-policy/configure-dc-audit-privilege-use.md)**
* **[REQ-DC-145 - Audit Policy: System Events Auditing](audit-policy/configure-dc-audit-system-events.md)**
