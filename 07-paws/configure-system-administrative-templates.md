# [REQ-PAW-029] Configure System Administrative Templates for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies grouped by their GPO nodes:

#### Network & TCP/IP Settings
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation`
  * **Configure SMB v1 client driver**: Set to `Enabled`, select `Disable driver (recommended)`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server`
  * **Configure SMB v1 server**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\TCPIP Settings\Parameters`
  * **NetBT NodeType configuration**: Set to `Enabled`, select `P-node (recommended)`

#### Legacy Security Options (MSS Settings)
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * Configure the following security settings (deploy via GPO Preferences Registry if Custom ADMX templates are not available):
    * **MSS: (AutoAdminLogon) Enable Automatic Logon**: Set to `Disabled`
    * **MSS: (DisableIPSourceRouting IPv6) IP source routing protection level**: Set to `Enabled: Highest protection, source routing is completely disabled`
    * **MSS: (DisableIPSourceRouting) IP source routing protection level**: Set to `Enabled: Highest protection, source routing is completely disabled`
    * **MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes**: Set to `Disabled`
    * **MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers**: Set to `Enabled`
    * **MSS: (SafeDllSearchMode) Enable Safe DLL search mode**: Set to `Enabled`
    * **MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires**: Set to `Enabled: 5 or fewer seconds`
    * **MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning**: Set to `Enabled: 90% or less`

#### System & Group Policy Settings
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Device Installation`
  * **Prevent device metadata retrieval from the Internet**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Group Policy`
  * **Configure registry policy processing**: Set to `Enabled`
    * Uncheck: `Do not apply during periodic background processing`
    * Check: `Process even if the Group Policy objects have not changed`
  * **Configure security policy processing**: Set to `Enabled`
    * Uncheck: `Do not apply during periodic background processing`
    * Check: `Process even if the Group Policy objects have not changed`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Cross-Device Experiences`
  * **Continue experiences on this device**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
  * **Turn off downloading of print drivers over HTTP**: Set to `Enabled`
  * **Turn off Internet download for Web publishing and online ordering wizards**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Local Security Authority`
  * **Allow Custom SSPs and APs to be loaded into LSASS**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Logon`
  * **Block user from showing account details on sign-in**: Set to `Enabled`
  * **Do not display network selection UI**: Set to `Enabled`
  * **Do not enumerate connected users on domain-joined computers**: Set to `Enabled`
  * **Turn off app notifications on the lock screen**: Set to `Enabled`
  * **Turn off picture password sign-in**: Set to `Enabled`
  * **Turn on convenience PIN sign-in**: Set to `Disabled`
  * **Prevent the use of security questions for local accounts**: Set to `Enabled`
  * **Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings`
  * **Allow network connectivity during connected-standby (on battery)**: Set to `Disabled`
  * **Allow network connectivity during connected-standby (plugged in)**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Assistance`
  * **Configure Offer Remote Assistance**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Remote Procedure Call`
  * **Enable RPC Endpoint Mapper Client Authentication**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Windows Time Service\Time Providers`
  * **Enable Windows NTP Client**: Set to `Enabled`
  * **Enable Windows NTP Server**: Set to `Disabled`

#### Windows Components Settings
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment`
  * **Not allow per-user unsigned packages to install by default (requires explicitly allow per install)**: Set to `Enabled`
  * **Prevent non-admin users from installing packaged Windows apps**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Biometrics\Facial Features`
  * **Configure enhanced anti-spoofing**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content`
  * **Turn off cloud consumer account state content**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Connect`
  * **Require pin for pairing**: Set to `Enabled` (Select `First Time` or `Always`)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Credential User Interface`
  * **Do not display the password reveal button**: Set to `Enabled`
  * **Enumerate administrator accounts on elevation**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds`
  * **Disable OneSettings Downloads**: Set to `Enabled`
  * **Do not show feedback notifications**: Set to `Enabled`
  * **Enable OneSettings Auditing**: Set to `Enabled`
  * **Limit Diagnostic Log Collection**: Set to `Enabled`
  * **Limit Dump Collection**: Set to `Enabled`
  * **Toggle user control over Insider builds**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\App Installer`
  * **Enable App Installer Experimental Features**: Set to `Disabled`
  * **Enable App Installer Hash Override**: Set to `Disabled`
  * **Enable App Installer Local Archive Malware Scan Override**: Set to `Disabled`
  * **Enable App Installer Microsoft Store Source Certificate Validation Bypass**: Set to `Disabled`
  * **Enable App Installer ms-appinstaller protocol**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Application`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
  * **Specify the maximum log file size (KB)**: Set to `Enabled`, set maximum log size to `32768`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Security`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
  * **Specify the maximum log file size (KB)**: Set to `Enabled`, set maximum log size to `196608`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\Setup`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
  * **Specify the maximum log file size (KB)**: Set to `Enabled`, set maximum log size to `32768`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Event Log Service\System`
  * **Control Event Log behavior when the log file reaches its maximum size**: Set to `Disabled`
  * **Specify the maximum log file size (KB)**: Set to `Enabled`, set maximum log size to `32768`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\File Explorer`
  * **Do not apply the Mark of the Web tag to files copied from insecure sources**: Set to `Disabled`
  * **Turn off shell protocol protected mode**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer`
  * **Disable Internet Explorer 11 as a standalone browser**: Set to `Enabled`, select `Always`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Internet Explorer\Feeds`
  * **Prevent downloading of enclosures**: Set to `Enabled`
  * **Turn on Basic feed authentication over HTTP**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Remediation\Behavioral Network Blocks\Brute Force Protection`
  * **Configure Remote Encryption Protection Mode**: Set to `Enabled` (Select `Audit` or higher)
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan`
  * **Turn off scanning of packed executables**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Defender Security Center\App and Browser protection`
  * **Prevent users from modifying settings**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Search`
  * **Allow Cortana**: Set to `Disabled`
  * **Allow Cortana above lock screen**: Set to `Disabled`
  * **Allow indexing of encrypted files**: Set to `Disabled`
  * **Allow search and Cortana to use location**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Store`
  * **Turn off Automatic Download and Install of updates**: Set to `Disabled`
  * **Turn off the offer to update to the latest version of Windows**: Set to `Enabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Widgets`
  * **Allow widgets**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Logon Options`
  * **Sign-in and lock last interactive user automatically after a restart**: Set to `Disabled`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Sandbox`
  * **Allow clipboard sharing with Windows Sandbox**: Set to `Disabled`
  * **Allow networking in Windows Sandbox**: Set to `Disabled`

#### Windows Update Settings
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update` (or `Windows Update\Manage end user experience` depending on ADMX version)
  * **Remove access to “Pause updates” feature**: Set to `Enabled`
  * **Manage preview builds**: Set to `Disabled`
  * **Select when Preview Builds and Feature Updates are received**: Set to `Enabled`, set Defer Feature Updates Period in Days to `180` (or more)
  * **Select when Quality Updates are received**: Set to `Enabled`, set Defer Quality Updates Period in Days to `0`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Update\Manage end user experience` (or standard `Windows Update\AU` depending on ADMX version)
  * **Configure Automatic Updates**: Set to `Enabled`, select `Scheduled install day` = `0 - Every day`
  * **No auto-restart with logged on users for scheduled automatic updates installations**: Set to `Disabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative templates registry values on PAWs.

[Download Script: Configure-PawSystemAdministrativeTemplates.ps1](implementation_scripts/Configure-PawSystemAdministrativeTemplates.ps1)

```powershell
# Configure-PawSystemAdministrativeTemplates.ps1
# Description: Configures system and administrative template controls for PAWs.

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

Write-Host "[+] PAW administrative templates configured successfully." -ForegroundColor Green
```

*To verify the administrative template configuration on the PAW:*

[Download Script: Get-PawSystemAdministrativeTemplatesStatus.ps1](audit_scripts/Get-PawSystemAdministrativeTemplatesStatus.ps1)

```powershell
# Get-PawSystemAdministrativeTemplatesStatus.ps1
# Description: Audits 84 system and administrative template controls on the local PAW.

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
Test-RegValue -RecNum "18.10.58.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "DisableEnclosureDownload" -ExpectedValue 1
Test-RegValue -RecNum "18.10.58.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "AllowBasicAuthInClear" -ExpectedValue 0
Test-RegValue -RecNum "18.10.43.11.1.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" -ValueName "BruteForceProtectionConfiguredState" -ExpectedValue 2
Test-RegValue -RecNum "18.10.43.13.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisablePackedExeScanning" -ExpectedValue 0
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
Test-RegValue -RecNum "18.10.93.2.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetDisablePauseUXAccess" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ManagePreviewBuildsPolicyValue" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.2.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -ExpectedValue 0
Test-RegValue -RecNum "18.10.93.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -ExpectedValue 0

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
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 18.2 to 18.10 Administrative template rules.
* **Microsoft Windows Security Baselines**: Computer and updates client configuration parameters.
* **DoD Windows 11 Computer STIG v2r6**: Event log, update client, network parameters, and device install templates.
* **ANSSI AD Hardening Guide**: Recommendations on disabling legacy protocols (SMBv1, etc.) and enforcing cryptographic checks.
