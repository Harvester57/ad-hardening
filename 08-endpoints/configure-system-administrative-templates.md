# [REQ-END-026] Configure System Administrative Templates

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\...`
  * **Registry Location**: Multiple locations under `HKLM\SOFTWARE\Policies` and `HKLM\SYSTEM\CurrentControlSet` (see details below)

---

## Rationale
Administrative templates govern system-wide capabilities, behaviors, and diagnostic logging. Hardening these configurations reduces the attack surface and mitigates privilege escalation, credential theft, and unauthorized software installation:

1. **Protocols Hardening**: Disabling legacy SMBv1 client/server components prevents exploitation of known protocol flaws. Configuring NetBIOS NodeType to P-Node prevents name resolution fallback issues.
2. **Data Collection & Telemetry**: Disabling Insider builds, telemetry feedback, widgets, Cortana, and OneSettings downloads blocks potential information disclosure paths and aligns with clean enterprise environments.
3. **App and Installer Restrictions**: Preventing non-admin users from installing packaged apps, limiting App Installer protocol handlers (`ms-appinstaller`), and disabling experimental installer features mitigates malware installation vectors.
4. **Event Log Sizes**: Increasing maximum log file sizes (Application/Setup/System to 32,768 KB, Security to 196,608 KB) ensures security events are retained long enough for compliance auditing and forensic analysis.
5. **Windows Update Controls**: Restricting update pauses and configuring daily update checks ensure client systems remain persistently patched.

---

## Legacy Impact & Compatibility
* **App Installers**: Disabling `ms-appinstaller` protocol handlers will block users from web-installing applications through the Appx installer interface.
* **IE11 Standalone**: Disabling Internet Explorer 11 blocks the standalone browser, redirecting users to Microsoft Edge.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure the administrative template settings in GPMC according to the paths and values detailed below:

| Recommendation | Title | Registry Path | Value Name | Value Type | Expected Value |
| --- | --- | --- | --- | --- | --- |
| 18.4.2 | (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' | `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10` | `Start` | `REG_DWORD` | 0x00000004 (4) |
| 18.4.3 | (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled' | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `SMB1` | `REG_DWORD` | 0x00000000 (0) |
| 18.4.7 | (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' | `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters` | `NodeType` | `REG_DWORD` | 0x00000002 (2) |
| 18.5.1 | (L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled' | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `AutoAdminLogon` | `REG_SZ` | "0" |
| 18.5.2 | (L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters` | `DisableIPSourceRouting` | `REG_DWORD` | 0x00000002 (2) |
| 18.5.3 | (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled' | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | `DisableIPSourceRouting` | `REG_DWORD` | 0x00000002 (2) |
| 18.5.5 | (L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' | `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | `EnableICMPRedirect` | `REG_DWORD` | 0x00000000 (0) |
| 18.5.7 | (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' | `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters` | `NoNameReleaseOnDemand` | `REG_DWORD` | 0x00000001 (1) |
| 18.5.9 | (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled' | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` | `SafeDllSearchMode` | `REG_DWORD` | 0x00000001 (1) |
| 18.5.10 | (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires' is set to 'Enabled: 5 or fewer seconds' | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `ScreenSaverGracePeriod` | `REG_DWORD` | 0x00000005 (5) |
| 18.5.13 | (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less' | `HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security` | `WarningLevel` | `REG_DWORD` | 0x0000005a (90) |
| 18.9.7.2 | (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata` | `PreventDeviceMetadataFromNetwork` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.19.2 | (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` | `NoBackgroundPolicy` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.19.3 | (L1) Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` | `NoGPOListChanges` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.19.4 | (L1) Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` | `NoBackgroundPolicy` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.19.5 | (L1) Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` | `NoGPOListChanges` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.19.6 | (L1) Ensure 'Continue experiences on this device' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `EnableCdp` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.20.1.2 | (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers` | `DisableWebPnPDownload` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.20.1.6 | (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoWebServices` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.26.1 | (L1) Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `AllowCustomSSPsAPs` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.28.1 | (L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `BlockUserFromShowingAccountDetailsOnSignin` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.28.2 | (L1) Ensure 'Do not display network selection UI' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `DontDisplayNetworkSelectionUI` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.28.3 | (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `DontEnumerateConnectedUsers` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.28.5 | (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `DisableLockScreenAppNotifications` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.28.6 | (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `BlockDomainPicturePassword` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.28.7 | (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `AllowDomainPINLogon` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.33.6.1 | (L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9` | `DCSettingIndex` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.33.6.2 | (L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9` | `ACSettingIndex` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.35.1 | (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | `fAllowUnsolicited` | `REG_DWORD` | 0x00000000 (0) |
| 18.9.36.1 | (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc` | `EnableAuthEpResolution` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.51.1.1 | (L1) Ensure 'Enable Windows NTP Client' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient` | `Enabled` | `REG_DWORD` | 0x00000001 (1) |
| 18.9.51.1.2 | (L1) Ensure 'Enable Windows NTP Server' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer` | `Enabled` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.4.2 | (L1) Ensure 'Not allow per-user unsigned packages to install by default (requires explicitly allow per install)' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx` | `DisablePerUserUnsignedPackagesByDefault` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.4.3 | (L1) Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx` | `BlockNonAdminUserInstall` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.9.1.1 | (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures` | `EnhancedAntiSpoofing` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.13.1 | (L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | `DisableConsumerAccountStateContent` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.14.1 | (L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect` | `RequirePinForPairing` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.15.1 | (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI` | `DisablePasswordReveal` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.15.2 | (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled' | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI` | `EnumerateAdministrators` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.15.3 | (L1) Ensure 'Prevent the use of security questions for local accounts' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `NoLocalPasswordResetQuestions` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.3 | (L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `DisableOneSettingsDownloads` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.4 | (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `DoNotShowFeedbackNotifications` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.5 | (L1) Ensure 'Enable OneSettings Auditing' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `EnableOneSettingsAuditing` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.6 | (L1) Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `LimitDiagnosticLogCollection` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.7 | (L1) Ensure 'Limit Dump Collection' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `LimitDumpCollection` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.16.8 | (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds` | `AllowBuildPreview` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.18.2 | (L1) Ensure 'Enable App Installer Experimental Features' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` | `EnableExperimentalFeatures` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.18.3 | (L1) Ensure 'Enable App Installer Hash Override' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` | `EnableHashOverride` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.18.4 | (L1) Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` | `EnableLocalArchiveMalwareScanOverride` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.18.5 | (L1) Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` | `EnableBypassCertificatePinningForMicrosoftStore` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.18.6 | (L1) Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller` | `EnableMSAppInstallerProtocol` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.26.1.1 | (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application` | `Retention` | `REG_SZ` | "0" |
| 18.10.26.1.2 | (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application` | `MaxSize` | `REG_DWORD` | 0x00008000 (32768) |
| 18.10.26.2.1 | (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security` | `Retention` | `REG_SZ` | "0" |
| 18.10.26.2.2 | (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security` | `MaxSize` | `REG_DWORD` | 0x00030000 (196608) |
| 18.10.26.3.1 | (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup` | `Retention` | `REG_SZ` | "0" |
| 18.10.26.3.2 | (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup` | `MaxSize` | `REG_DWORD` | 0x00008000 (32768) |
| 18.10.26.4.1 | (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System` | `Retention` | `REG_SZ` | "0" |
| 18.10.26.4.2 | (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System` | `MaxSize` | `REG_DWORD` | 0x00008000 (32768) |
| 18.10.29.3 | (L1) Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer` | `DisableMotWOnInsecurePathCopy` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.29.5 | (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `PreXPSP2ShellProtocolBehavior` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.35.1 | (L1) Ensure 'Disable Internet Explorer 11 as a standalone browser' is set to 'Enabled: Always' | `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main` | `NotifyDisableIEOptions` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.43.11.1.1.2 | (L1) Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection` | `BruteForceProtectionConfiguredState` | `REG_DWORD` | 0x00000002 (2) |
| 18.10.43.13.2 | (L1) Ensure 'Scan packed executables' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan` | `DisablePackedExeScanning` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.58.1 | (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds` | `DisableEnclosureDownload` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.58.2 | (L1) Ensure 'Turn on Basic feed authentication over HTTP' is set to 'Disabled' | `HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds` | `AllowBasicAuthInClear` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.59.3 | (L1) Ensure 'Allow Cortana' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `AllowCortana` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.59.4 | (L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `AllowCortanaAboveLock` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.59.5 | (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `AllowIndexingEncryptedStoresOrItems` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.59.6 | (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` | `AllowSearchToUseLocation` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.66.2 | (L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore` | `AutoDownload` | `REG_DWORD` | 0x00000004 (4) |
| 18.10.66.3 | (L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore` | `DisableOSUpgrade` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.72.1 | (L1) Ensure 'Allow widgets' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` | `AllowNewsAndInterests` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.82.1 | (L1) Ensure 'Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.' is set to 'Disabled' | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `EnableMPR` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.82.2 | (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` | `DisableAutomaticRestartSignOn` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.91.1 | (L1) Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox` | `AllowClipboardRedirection` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.91.2 | (L1) Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox` | `AllowNetworking` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.92.2.1 | (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection` | `DisallowExploitProtectionOverride` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.93.1.1 | (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` | `NoAutoRebootWithLoggedOnUsers` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.93.2.2 | (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` | `ScheduledInstallDay` | `REG_DWORD` | 0x00000000 (0) |
| 18.10.93.2.3 | (L1) Ensure 'Remove access to “Pause updates” feature' is set to 'Enabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `SetDisablePauseUXAccess` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.93.4.1 | (L1) Ensure 'Manage preview builds' is set to 'Disabled' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `ManagePreviewBuildsPolicyValue` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.93.4.2 | (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `DeferFeatureUpdates` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.93.4.2 | (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `DeferFeatureUpdatesPeriodInDays` | `REG_DWORD` | 0x000000b4 (180) |
| 18.10.93.4.3 | (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `DeferQualityUpdates` | `REG_DWORD` | 0x00000001 (1) |
| 18.10.93.4.3 | (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | `DeferQualityUpdatesPeriodInDays` | `REG_DWORD` | 0x00000000 (0) |

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative templates registry values.

[Download Script: Configure-SystemAdministrativeTemplates.ps1](implementation_scripts/Configure-SystemAdministrativeTemplates.ps1)

```powershell
# Configure-SystemAdministrativeTemplates.ps1
# Description: Configures 84 system and administrative template controls for Windows Client hardening.

Write-Host "Applying System Administrative Templates hardening..." -ForegroundColor Cyan

# Key Path: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5 -Type DWord

# Key Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -Name "EnumerateAdministrators" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "PreXPSP2ShellProtocolBehavior" -Value 0 -Type DWord


# Key Path: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableMPR" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -Name "EnhancedAntiSpoofing" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Dsh
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -Name "DisableEnclosureDownload" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "NotifyDisableIEOptions" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -Name "Enabled" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -Name "Enabled" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -Name "DisallowExploitProtectionOverride" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" -Name "BruteForceProtectionConfiguredState" -Value 2 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisablePackedExeScanning" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\WindowsStore
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableLocalArchiveMalwareScanOverride" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableBypassCertificatePinningForMicrosoftStore" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Appx
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "DisablePerUserUnsignedPackagesByDefault" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "BlockNonAdminUserInstall" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" -Name "DisablePasswordReveal" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DisableOneSettingsDownloads" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "EnableOneSettingsAuditing" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "Retention" -Value "0" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -Name "MaxSize" -Value 32768 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "Retention" -Value "0" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -Name "MaxSize" -Value 196608 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "Retention" -Value "0" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -Name "MaxSize" -Value 32768 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "Retention" -Value "0" -Type String
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -Name "MaxSize" -Value 32768 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableMotWOnInsecurePathCopy" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoBackgroundPolicy" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -Name "NoGPOListChanges" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Sandbox
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\System
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdates" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferFeatureUpdatesPeriodInDays" -Value 180 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdates" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0 -Type DWord

# Key Path: HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord

# Key Path: HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord

# Key Path: HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds
if (-not (Test-Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds")) {
    New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name "AllowBasicAuthInClear" -Value 0 -Type DWord

Write-Host "[+] System administrative templates configured successfully." -ForegroundColor Green
```

*To verify the administrative template configuration:*

[Download Script: Get-SystemAdministrativeTemplatesStatus.ps1](audit_scripts/Get-SystemAdministrativeTemplatesStatus.ps1)

```powershell
# Get-SystemAdministrativeTemplatesStatus.ps1
# Description: Audits 84 system and administrative template controls on the local machine.

Write-Host "--- Auditing System Administrative Templates Hardening ---" -ForegroundColor Cyan
$script:Vulnerable = $false

function Test-RegValue {
    param(
        [string]$RecNum,
        [string]$Hive,
        [string]$KeyPath,
        [string]$ValueName,
        [object]$ExpectedValue
    )
    $FullPath = "$($Hive):\$($KeyPath)"
    if (Test-Path $FullPath) {
        $Prop = Get-ItemProperty -Path $FullPath -Name $ValueName -ErrorAction SilentlyContinue
        if ($null -ne $Prop) {
            $ActualValue = $Prop.$ValueName
            if ($ActualValue -eq $ExpectedValue) {
                Write-Host "  [+] $RecNum | $ValueName = $ActualValue (Secure)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $RecNum | Path: $Hive\$KeyPath | Value: $ValueName | Current: $ActualValue (Expected: $ExpectedValue)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        } else {
            Write-Host "  [!] MISSING VALUE: $RecNum | Path: $Hive\$KeyPath | Value: $ValueName (Expected: $ExpectedValue)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING KEY: $RecNum | Path: $Hive\$KeyPath (Expected: $ValueName = $ExpectedValue)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

Test-RegValue -RecNum "18.4.2" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\mrxsmb10" -ValueName "Start" -ExpectedValue 4
Test-RegValue -RecNum "18.4.3" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -ExpectedValue 0
Test-RegValue -RecNum "18.4.7" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -ExpectedValue 2
Test-RegValue -RecNum "18.5.1" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AutoAdminLogon" -ExpectedValue "0"
Test-RegValue -RecNum "18.5.2" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisableIPSourceRouting" -ExpectedValue 2
Test-RegValue -RecNum "18.5.3" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "DisableIPSourceRouting" -ExpectedValue 2
Test-RegValue -RecNum "18.5.5" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableICMPRedirect" -ExpectedValue 0
Test-RegValue -RecNum "18.5.7" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NoNameReleaseOnDemand" -ExpectedValue 1
Test-RegValue -RecNum "18.5.9" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "SafeDllSearchMode" -ExpectedValue 1
Test-RegValue -RecNum "18.5.10" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScreenSaverGracePeriod" -ExpectedValue 5
Test-RegValue -RecNum "18.5.13" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -ValueName "WarningLevel" -ExpectedValue 90
Test-RegValue -RecNum "18.9.7.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ValueName "PreventDeviceMetadataFromNetwork" -ExpectedValue 1
Test-RegValue -RecNum "18.9.19.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoBackgroundPolicy" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoGPOListChanges" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoBackgroundPolicy" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoGPOListChanges" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableCdp" -ExpectedValue 0
Test-RegValue -RecNum "18.9.20.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName "DisableWebPnPDownload" -ExpectedValue 1
Test-RegValue -RecNum "18.9.20.1.6" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoWebServices" -ExpectedValue 1
Test-RegValue -RecNum "18.9.26.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowCustomSSPsAPs" -ExpectedValue 0
Test-RegValue -RecNum "18.9.28.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "BlockUserFromShowingAccountDetailsOnSignin" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontDisplayNetworkSelectionUI" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontEnumerateConnectedUsers" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "BlockDomainPicturePassword" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.7" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowDomainPINLogon" -ExpectedValue 0
Test-RegValue -RecNum "18.9.33.6.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -ValueName "DCSettingIndex" -ExpectedValue 0
Test-RegValue -RecNum "18.9.33.6.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -ValueName "ACSettingIndex" -ExpectedValue 0
Test-RegValue -RecNum "18.9.35.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowUnsolicited" -ExpectedValue 0
Test-RegValue -RecNum "18.9.36.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -ValueName "EnableAuthEpResolution" -ExpectedValue 1
Test-RegValue -RecNum "18.9.51.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -ValueName "Enabled" -ExpectedValue 1
Test-RegValue -RecNum "18.9.51.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -ValueName "Enabled" -ExpectedValue 0
Test-RegValue -RecNum "18.10.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Appx" -ValueName "DisablePerUserUnsignedPackagesByDefault" -ExpectedValue 1
Test-RegValue -RecNum "18.10.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Appx" -ValueName "BlockNonAdminUserInstall" -ExpectedValue 1
Test-RegValue -RecNum "18.10.9.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -ValueName "EnhancedAntiSpoofing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.13.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableConsumerAccountStateContent" -ExpectedValue 1
Test-RegValue -RecNum "18.10.14.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Connect" -ValueName "RequirePinForPairing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.15.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\CredUI" -ValueName "DisablePasswordReveal" -ExpectedValue 1
Test-RegValue -RecNum "18.10.15.2" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -ValueName "EnumerateAdministrators" -ExpectedValue 0
Test-RegValue -RecNum "18.10.15.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "NoLocalPasswordResetQuestions" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "DisableOneSettingsDownloads" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "DoNotShowFeedbackNotifications" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "EnableOneSettingsAuditing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDiagnosticLogCollection" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.7" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDumpCollection" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.8" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "AllowBuildPreview" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableExperimentalFeatures" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableHashOverride" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableLocalArchiveMalwareScanOverride" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableBypassCertificatePinningForMicrosoftStore" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableMSAppInstallerProtocol" -ExpectedValue 0
Test-RegValue -RecNum "18.10.26.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.26.2.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.2.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -ExpectedValue 196608
Test-RegValue -RecNum "18.10.26.3.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.3.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.26.4.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.29.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "DisableMotWOnInsecurePathCopy" -ExpectedValue 0
Test-RegValue -RecNum "18.10.29.5" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "PreXPSP2ShellProtocolBehavior" -ExpectedValue 0
Test-RegValue -RecNum "18.10.35.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "NotifyDisableIEOptions" -ExpectedValue 1
Test-RegValue -RecNum "18.10.43.11.1.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" -ValueName "BruteForceProtectionConfiguredState" -ExpectedValue 2
Test-RegValue -RecNum "18.10.43.13.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisablePackedExeScanning" -ExpectedValue 0
Test-RegValue -RecNum "18.10.58.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "DisableEnclosureDownload" -ExpectedValue 1
Test-RegValue -RecNum "18.10.58.2" -Hive "HKLM" -KeyPath "Software\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "AllowBasicAuthInClear" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortana" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortanaAboveLock" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowIndexingEncryptedStoresOrItems" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowSearchToUseLocation" -ExpectedValue 0
Test-RegValue -RecNum "18.10.66.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "AutoDownload" -ExpectedValue 4
Test-RegValue -RecNum "18.10.66.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "DisableOSUpgrade" -ExpectedValue 1
Test-RegValue -RecNum "18.10.72.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Dsh" -ValueName "AllowNewsAndInterests" -ExpectedValue 0
Test-RegValue -RecNum "18.10.82.1" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableMPR" -ExpectedValue 0
Test-RegValue -RecNum "18.10.82.2" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableAutomaticRestartSignOn" -ExpectedValue 1
Test-RegValue -RecNum "18.10.91.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Sandbox" -ValueName "AllowClipboardRedirection" -ExpectedValue 0
Test-RegValue -RecNum "18.10.91.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Sandbox" -ValueName "AllowNetworking" -ExpectedValue 0
Test-RegValue -RecNum "18.10.92.2.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" -ValueName "DisallowExploitProtectionOverride" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -ExpectedValue 0
Test-RegValue -RecNum "18.10.93.2.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -ExpectedValue 0
Test-RegValue -RecNum "18.10.93.2.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetDisablePauseUXAccess" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ManagePreviewBuildsPolicyValue" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdatesPeriodInDays" -ExpectedValue 180
Test-RegValue -RecNum "18.10.93.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdatesPeriodInDays" -ExpectedValue 0

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 18.4, 18.5, 18.9, and 18.10 (System Administrative Templates settings)
* **ANSSI Active Directory Hardening Guide**: Recommendations on local account password management and protocol minimization
* **Microsoft Security Baseline**: Windows Client Security Baseline recommendations
