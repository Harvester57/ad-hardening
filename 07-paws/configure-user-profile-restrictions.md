# [REQ-PAW-024] Configure User Profile Restrictions

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications
    * User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content
    * User Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options
    * User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager
    * User Configuration\Policies\Administrative Templates\Windows Components\Network Sharing
    * Computer Configuration\Administrative Templates\Control Panel\Personalization
    * Computer Configuration\Administrative Templates\System\Group Policy
    * Computer Configuration\Administrative Templates\Windows Components\App Privacy
    * Computer Configuration\Administrative Templates\Windows Components\Application Compatibility
    * Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds
    * Computer Configuration\Administrative Templates\Windows Components\Explorer
    * Computer Configuration\Administrative Templates\Windows Components\Game DVR
    * Computer Configuration\Administrative Templates\Windows Components\Windows Ink Workspace
    * Computer Configuration\Administrative Templates\Windows Components\Windows Installer
    * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
  * **Registry Locations**:
    * HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications
      * `NoToastApplicationNotificationOnLockScreen` = `1` (REG_DWORD)
    * HKCU\Software\Policies\Microsoft\Windows\CloudContent
      * `DisableThirdPartySuggestions` = `1` (REG_DWORD)
      * `ConfigureWindowsSpotlight` = `2` (REG_DWORD)
      * `DisableSpotlightCollectionOnDesktop` = `1` (REG_DWORD)
    * HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot
      * `TurnOffWindowsCopilot` = `1` (REG_DWORD)
    * HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
      * `NoInplaceSharing` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization
      * `AllowInputPersonalization` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments
      * `SaveZoneInformation` = `2` (REG_DWORD)
    * HKLM\SOFTWARE\Classes\batfile\shell\runasuser, cmdfile\shell\runasuser, exefile\shell\runasuser, mscfile\shell\runasuser
      * `SuppressionPolicy` = `4096` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel
      * `DisableExceptionChainValidation` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization
      * `NoLockScreenCamera` = `1` (REG_DWORD)
      * `NoLockScreenSlideshow` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
      * `NoBackgroundPolicy` = `0` (REG_DWORD)
      * `NoGPOListChanges` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy
      * `LetAppsActivateWithVoiceAboveLock` = `2` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat
      * `DisableInventory` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent
      * `DisableWindowsConsumerFeatures` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
      * `AllowTelemetry` = `1` (REG_DWORD)
      * `LimitEnhancedDiagnosticDataWindowsAnalytics` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer
      * `NoDataExecutionPrevention` = `0` (REG_DWORD)
      * `NoHeapTerminationOnCorruption` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
      * `PreXPSP2ShellProtocolBehavior` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main
      * `NotifyDisableIEOptions` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds
      * `DisableEnclosureDownload` = `1` (REG_DWORD)
      * `AllowBasicAuthInClear` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
      * `DisableAutomaticRestartSignOn` = `1` (REG_DWORD)
      * `InactivityTimeoutSecs` = `900` (REG_DWORD)
      * `LegalNoticeText` = `"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring."` (REG_SZ)
      * `LegalNoticeCaption` = `"US Department of Defense Warning Statement"` (REG_SZ)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
      * `EnableUserControl` = `0` (REG_DWORD)
      * `AlwaysInstallElevated` = `0` (REG_DWORD)
      * `SafeForScripting` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR
      * `AllowGameDVR` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace
      * `AllowWindowsInkWorkspace` = `1` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
      * `ProtectionMode` = `1` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\seclogon
      * `Start` = `4` (REG_DWORD, Disabled)
    * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
      * `MoveImages` = `0xFFFFFFFF` (REG_DWORD, force ASLR for relocatable images)
      * `FeatureSettingsOverride` = `72` (REG_DWORD, enable speculative execution mitigations)
      * `FeatureSettingsOverrideMask` = `3` (REG_DWORD, mask for mitigations)
    * HKLM\Software\Microsoft\Cryptography\Wintrust\Config (and Wow6432Node equivalent)
      * `EnableCertPaddingCheck` = `1` (REG_DWORD, strict Authenticode cert padding verification)
    * HKLM\SOFTWARE\Microsoft\Command Processor
      * `LockBatchFilesWhenInUse` = `1` (REG_DWORD, secure mode for batch file processing)
    * HKLM\SOFTWARE\Microsoft\TTD
      * `RecordingPolicy` = `2` (REG_DWORD, disable Time-Travel Debugging)
    * HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots
      * `Flags` = `1` (REG_DWORD, prevent standard users from installing root certificates)
    * HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows
      * `LoadAppInit_DLLs` = `0` (REG_DWORD, disable custom DLL loading list)
    * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer
      * `DisableCoInstallers` = `1` (REG_DWORD, block driver co-installer execution)

---

## Rationale
Securing user profile characteristics and administrative explorer behaviors prevents exposure of sensitive information, restricts arbitrary file execution pathways, disables unapproved telemetry/consumer features, and locks down potential privilege escalation points:

1. **Lock Screen Toast Notifications (`NoToastApplicationNotificationOnLockScreen`)**: By default, Windows displays application notifications (toasts) on the lock screen. This includes email snippets, messaging notifications, or Multi-Factor Authentication (MFA) codes. If a workstation is left locked, anyone with physical sight of the screen can read these notifications, leaking corporate secrets or bypassing authentication challenges. Disabling these toasts on the lock screen prevents this exposure.
2. **Third-Party Consumer Experiences (`DisableThirdPartySuggestions` & `DisableWindowsConsumerFeatures`)**: Windows Spotlight frequently recommends third-party software, applications, or advertising on the lock screen and Start menu. Disabling third-party content prevents telemetry generation, unapproved software installation prompts, and social-engineering entry points.
3. **Shell Context Menu runasuser Bypass (`SuppressionPolicy`)**: Restricting the "Run as different user" shell context menus prevents standard users from attempting to launch executables under different identities without triggering formal security validation or UAC controls.
4. **Kernel SEHOP (`DisableExceptionChainValidation`)**: Structured Exception Handler Overwrite Protection (SEHOP) detects and blocks stack-based buffer overflow exploit redirection techniques at the OS level.
5. **Explorer and Installer Hardening (`AlwaysInstallElevated`, `EnableUserControl`)**: Forcing standard user installer locks and disabling elevated installations prevents users from escalating privileges using crafted installer files.
6. **Inactivity Timeout (`InactivityTimeoutSecs`)**: Automatically locking idle workstations after 15 minutes of inactivity (900 seconds) prevents physical session hijacking.
7. **Memory Protection & ASLR Enforcement (`MoveImages`)**: Address Space Layout Randomization (ASLR) makes it difficult for exploit payloads to find precise memory locations of APIs or system functions. Forcing ASLR on relocatable images ensures binary mitigation compliance.
8. **Strict Authenticode Signature Verification (`EnableCertPaddingCheck`)**: Prevents signature manipulation by enforcing strict padding validation, blocking attempts to append malicious payloads to signed binaries without invalidating the signature.
9. **Secure Batch processing (`LockBatchFilesWhenInUse`)**: Holds an opportunistic lock on batch/cmd scripts during execution to prevent files from being modified on-the-fly, which mitigates race conditions and statement-modification exploits.
10. **Disable Debugging & Telemetry abuse (`RecordingPolicy`, `DisableCoInstallers`, `LoadAppInit_DLLs`)**: Disabling Time-Travel Debugging prevents adversaries from dumping memory or executing arbitrary binaries. Disabling custom DLL loading (AppInit_DLLs) blocks persistent user-mode DLL injection. Disabling driver co-installers prevents unauthorized executable downloads during peripheral plugin.
11. **Standard User Root Certificate Restriction (`Flags` under `ProtectedRoots`)**: Restricting certificate store installation to administrators prevents standard users from importing rogue root certificate authorities into their personal store, which blocks internal MitM or code-signing forgery attacks.
12. **Spectre & Meltdown CPU Mitigations (`FeatureSettingsOverride`)**: Hardware-level speculative execution vulnerabilities can allow a malicious process to leak kernel memory. Enforcing modern speculative execution overrides blocks these side-channel exploitation paths.

---

## Legacy Impact & Compatibility
* **User Experience**: Users will still receive notifications while logged in and unlocked. However, when the workstation is locked, they will only see system status indicators, not detailed content banners.
* **Spotlight Aesthetics**: The lock screen background can still show administrative wallpaper choices, but will not query online Microsoft consumer recommendations.
* **Installer Failures**: Administrators will need to perform standard GPO-based software distribution or elevate installers manually, since "AlwaysInstallElevated" is securely disabled.
* **Driver Installations**: Blocking co-installers means manufacturer companion software for USB devices must be downloaded and installed manually by an administrator.
* **Legacy Application Compatibility**:
  * Some legacy software relying on custom DLL injection via AppInit_DLLs will fail to load their helper libraries.
  * Forcing ASLR may cause stability issues in older 32-bit executables or unsigned drivers. Proper sandbox verification is required.
  * Batch files that are dynamically self-modifying during runtime will fail when secure batch processing is enabled due to opportunistic file locks.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To apply user configuration settings, link the GPO to OUs containing user accounts (or enable GPO Loopback Processing on the computer policy).

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Configure the following settings:

#### 1. User Configuration
Navigate to: `User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications`
* **Policy**: `Turn off toast notifications on the lock screen` -> Set to **Enabled**

Navigate to: `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content`
* **Policy**: `Do not suggest third-party content in Windows spotlight` -> Set to **Enabled**
* **Policy**: `Configure Windows spotlight on lock screen` -> Set to **Disabled**
* **Policy**: `Turn off Spotlight collection on Desktop` -> Set to **Enabled**
* **Policy**: `Turn off Windows Copilot` -> Set to **Enabled**

Navigate to: `User Configuration\Policies\Administrative Templates\Control Panel\Regional and Language Options`
* **Policy**: `Allow users to enable online speech recognition services` -> Set to **Disabled**

Navigate to: `User Configuration\Policies\Administrative Templates\Windows Components\Attachment Manager`
* **Policy**: `Do not preserve zone information in file attachments` -> Set to **Disabled**

Navigate to: `User Configuration\Policies\Administrative Templates\Windows Components\Network Sharing`
* **Policy**: `Prevent users from sharing files within their profile.` -> Set to **Enabled**

#### 2. Computer Configuration (Personalization & System Restrictions)
Navigate to: `Computer Configuration\Administrative Templates\Control Panel\Personalization`
* **Policy**: `Prevent enabling lock screen camera` -> Set to **Enabled**
* **Policy**: `Prevent enabling lock screen slide show` -> Set to **Enabled**

Navigate to: `Computer Configuration\Administrative Templates\System\Group Policy`
* **Policy**: `Configure registry policy processing` -> Set to **Enabled**
  * Check **Process even if the Group Policy objects have not changed** -> Set to **Enabled** (value 1)
  * Check **Do not apply during periodic background processing** -> Set to **Disabled** (value 0)

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\App Privacy`
* **Policy**: `Let Windows apps activate with voice while the system is locked` -> Set to **Enabled: Force Deny**

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Application Compatibility`
* **Policy**: `Turn off Inventory Collector` -> Set to **Enabled**

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Cloud Content`
* **Policy**: `Turn off Microsoft consumer experiences` -> Set to **Enabled**

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Data Collection and Preview Builds`
* **Policy**: `Allow Diagnostic Data` -> Set to **Enabled: Send required diagnostic data** (value 1)
* **Policy**: `Limit optional diagnostic data for Desktop Analytics` -> Set to **Enabled** (value 1)

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Explorer`
* **Policy**: `Turn off Data Execution Prevention for Explorer` -> Set to **Disabled** (value 0)
* **Policy**: `Turn off heap termination on corruption` -> Set to **Disabled** (value 0)

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Game DVR`
* **Policy**: `Enables or disables Windows Game Recording and Broadcasting` -> Set to **Disabled** (value 0)

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Windows Ink Workspace`
* **Policy**: `Allow Windows Ink Workspace` -> Set to **Enabled: On, but disallow access above lock** (value 1)

Navigate to: `Computer Configuration\Administrative Templates\Windows Components\Windows Installer`
* **Policy**: `Allow user control over installs` -> Set to **Disabled** (value 0)
* **Policy**: `Always install with elevated privileges` -> Set to **Disabled** (value 0)
* **Policy**: `Prevent Internet Explorer security prompt for Windows Installer scripts` -> Set to **Disabled** (value 0)

Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
* **Policy**: `Interactive logon: Machine inactivity limit` -> Set to **900 seconds** (15 minutes)
* **Policy**: `Interactive logon: Message text for users attempting to log on` -> Set to warning message text
* **Policy**: `Interactive logon: Message title for users attempting to log on` -> Set to **US Department of Defense Warning Statement**
* **Policy**: `System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)` -> Set to **Enabled**
* **Policy**: `Devices: Allowed to format and eject removable media` -> Set to **Administrators**

#### 3. Deploy Custom Settings via GPO Preferences and System Mitigations
Configure GPO Preferences registry items or Administrative Templates for the remaining custom settings:
* **ASLR Force Randomization**: Enable in Exploit Guard mitigation policies or set registry `MoveImages` = `4294967295` (0xFFFFFFFF).
* **Spectre & Meltdown CPU Mitigations**: Configure registry `FeatureSettingsOverride` = `72` and `FeatureSettingsOverrideMask` = `3`.
* **LockBatchFilesWhenInUse**: Configure registry `LockBatchFilesWhenInUse` = `1` under `HKLM\SOFTWARE\Microsoft\Command Processor`.
* **EnableCertPaddingCheck**: Configure registry `EnableCertPaddingCheck` = `1` under `HKLM\Software\Microsoft\Cryptography\Wintrust\Config` (and Wow6432Node).
* **RecordingPolicy**: Configure registry `RecordingPolicy` = `2` under `HKLM\SOFTWARE\Microsoft\TTD`.
* **Root Cert Flags**: Configure registry `Flags` = `1` under `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots`.
* **LoadAppInit_DLLs**: Configure registry `LoadAppInit_DLLs` = `0` under `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows`.
* **DisableCoInstallers**: Configure registry `DisableCoInstallers` = `1` under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure user and system registry restrictions.

[Download Script: Set-PawUserProfileRestrictions.ps1](implementation_scripts/Set-PawUserProfileRestrictions.ps1)

```powershell
# Set-PawUserProfileRestrictions.ps1
# Description: Configures HKLM and HKCU registry settings for user profiles, shell behaviors, diagnostic data, installer locks, inactivity timeouts, and security policies on PAWs.

Write-Host "Applying User Profile and System Restrictions..." -ForegroundColor Cyan

# Helper function to create keys and set values safely
function Set-RegDWord {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$path,
        [string]$name,
        [int]$value
    )
    if ($PSCmdlet.ShouldProcess($path, "Set registry DWORD value $name to $value")) {
        $parent = Split-Path -Path $path
        if (-not (Test-Path $parent)) {
            New-Item -Path $parent -Force | Out-Null
        }
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
    }
}

function Set-RegString {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$path,
        [string]$name,
        [string]$value
    )
    if ($PSCmdlet.ShouldProcess($path, "Set registry string value $name to $value")) {
        $parent = Split-Path -Path $path
        if (-not (Test-Path $parent)) {
            New-Item -Path $parent -Force | Out-Null
        }
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force
    }
}

# 1. Enforce HKLM Registry Hardening Settings

# Shell RunAs Suppression Policies
Set-RegDWord "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" 4096
Set-RegDWord "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" 4096
Set-RegDWord "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" 4096
Set-RegDWord "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" 4096

# Kernel SEHOP
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" 0

# Personalization
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" 1

# Group Policy Behavior
$GpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
Set-RegDWord $GpKey "NoBackgroundPolicy" 0
Set-RegDWord $GpKey "NoGPOListChanges" 0

# App Privacy
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" 2

# App Compatibility
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" 1

# Cloud Content
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

# Data Collection / Telemetry
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" 1

# Explorer and Security Controls
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" 0
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" "NotifyDisableIEOptions" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" 0
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn" 1
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" 900

# Legal Notice Banner
$LegalText = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS, you consent to routine monitoring."
Set-RegString "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeText" $LegalText
Set-RegString "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption" "US Department of Defense Warning Statement"

# Installer Hardening
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" 0

# Game DVR
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0

# Windows Ink Workspace
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" 1

# System Objects Protection Mode
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" 1

# Secondary Logon Service (Disabled = 4)
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon" "Start" 4

# ASLR Force Randomization
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" 4294967295

# Strict Authenticode Cert Padding Check
Set-RegDWord "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" 1
Set-RegDWord "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" 1

# Secure Batch Processing
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" 1

# Disable Time-Travel Debugging (TTD)
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\TTD" "RecordingPolicy" 2

# Prevent standard users from installing root certificates
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" 1

# Disable AppInit_DLLs
Set-RegDWord "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" 0

# Block driver co-installers
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" "DisableCoInstallers" 1

# Spectre/Meltdown speculative execution mitigations
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" 72
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" 3

# Speech Recognition (AllowInputPersonalization = 0)
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" 0

# Attachment Manager (SaveZoneInformation = 2)
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" 2

Write-Host "[+] Local computer system restrictions applied." -ForegroundColor Green

# 2. Enforce HKCU Settings on Current User
$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
$CopilotPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
$ExplorerPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $PushPath)) { New-Item -Path $PushPath -Force | Out-Null }
Set-ItemProperty -Path $PushPath -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord -Force

if (-not (Test-Path $CloudPath)) { New-Item -Path $CloudPath -Force | Out-Null }
Set-ItemProperty -Path $CloudPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $CloudPath -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $CloudPath -Name "DisableSpotlightCollectionOnDesktop" -Value 1 -Type DWord -Force

if (-not (Test-Path $CopilotPath)) { New-Item -Path $CopilotPath -Force | Out-Null }
Set-ItemProperty -Path $CopilotPath -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force

if (-not (Test-Path $ExplorerPoliciesPath)) { New-Item -Path $ExplorerPoliciesPath -Force | Out-Null }
Set-ItemProperty -Path $ExplorerPoliciesPath -Name "NoInplaceSharing" -Value 1 -Type DWord -Force

Write-Host "[+] Current user profile restrictions applied successfully." -ForegroundColor Green

# 3. Enforce HKCU Settings on Default User Hive (For all future user profiles on this machine)
Write-Host "[*] Configuring Default User profile registry keys..." -ForegroundColor Gray
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"

if (Test-Path $DefaultHivePath) {
    # Load default hive
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    
    $DefaultPush = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $DefaultCloud = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    $DefaultCopilot = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot"
    $DefaultExplorer = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    if (-not (Test-Path $DefaultPush)) { New-Item -Path $DefaultPush -Force | Out-Null }
    Set-ItemProperty -Path $DefaultPush -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord -Force
    
    if (-not (Test-Path $DefaultCloud)) { New-Item -Path $DefaultCloud -Force | Out-Null }
    Set-ItemProperty -Path $DefaultCloud -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $DefaultCloud -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord -Force
    Set-ItemProperty -Path $DefaultCloud -Name "DisableSpotlightCollectionOnDesktop" -Value 1 -Type DWord -Force

    if (-not (Test-Path $DefaultCopilot)) { New-Item -Path $DefaultCopilot -Force | Out-Null }
    Set-ItemProperty -Path $DefaultCopilot -Name "TurnOffWindowsCopilot" -Value 1 -Type DWord -Force

    if (-not (Test-Path $DefaultExplorer)) { New-Item -Path $DefaultExplorer -Force | Out-Null }
    Set-ItemProperty -Path $DefaultExplorer -Name "NoInplaceSharing" -Value 1 -Type DWord -Force
    
    # Unload default hive
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
    
    Write-Host "[+] Default User registry template updated successfully." -ForegroundColor Green
} else {
    Write-Warning "Default User hive NTUSER.DAT not found."
}
```

*To audit local user profile configuration on the PAW:*

[Download Script: Test-PawUserProfileRestrictions.ps1](audit_scripts/Test-PawUserProfileRestrictions.ps1)

```powershell
# Test-PawUserProfileRestrictions.ps1
# Description: Checks HKCU and HKLM registry settings for active user and system profile restrictions on PAWs.

Write-Host "--- Auditing User Profile Restrictions ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue ($path, $name, $expectedValue) {
    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    $color = "Red"
    if ($actual -eq $expectedValue) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expectedValue')" -ForegroundColor $color
}

# 1. Audit Current User Settings
$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
$CopilotPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
$ExplorerPoliciesPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"

Test-RegistryValue $PushPath "NoToastApplicationNotificationOnLockScreen" 1
Test-RegistryValue $CloudPath "DisableThirdPartySuggestions" 1
Test-RegistryValue $CloudPath "ConfigureWindowsSpotlight" 2
Test-RegistryValue $CloudPath "DisableSpotlightCollectionOnDesktop" 1
Test-RegistryValue $CopilotPath "TurnOffWindowsCopilot" 1
Test-RegistryValue $ExplorerPoliciesPath "NoInplaceSharing" 1

# 2. Audit Computer HKLM Settings
$ClassBat = "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser"
$ClassCmd = "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser"
$ClassExe = "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser"
$ClassMsc = "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser"
Test-RegistryValue $ClassBat "SuppressionPolicy" 4096
Test-RegistryValue $ClassCmd "SuppressionPolicy" 4096
Test-RegistryValue $ClassExe "SuppressionPolicy" 4096
Test-RegistryValue $ClassMsc "SuppressionPolicy" 4096

$SessionKernel = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
Test-RegistryValue $SessionKernel "DisableExceptionChainValidation" 0

# Input Personalization and Attachment Manager
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" 0
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" 2

$Personalization = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
Test-RegistryValue $Personalization "NoLockScreenCamera" 1
Test-RegistryValue $Personalization "NoLockScreenSlideshow" 1

$GpKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
Test-RegistryValue $GpKey "NoBackgroundPolicy" 0
Test-RegistryValue $GpKey "NoGPOListChanges" 0

$AppPrivacy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
Test-RegistryValue $AppPrivacy "LetAppsActivateWithVoiceAboveLock" 2

$AppCompat = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
Test-RegistryValue $AppCompat "DisableInventory" 1

$CloudContent = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Test-RegistryValue $CloudContent "DisableWindowsConsumerFeatures" 1

$DataCollection = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Test-RegistryValue $DataCollection "AllowTelemetry" 1
Test-RegistryValue $DataCollection "LimitEnhancedDiagnosticDataWindowsAnalytics" 1

$Explorer = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
Test-RegistryValue $Explorer "NoDataExecutionPrevention" 0
Test-RegistryValue $Explorer "NoHeapTerminationOnCorruption" 0

$ExplorerPolicies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Test-RegistryValue $ExplorerPolicies "PreXPSP2ShellProtocolBehavior" 0

$IEMain = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
Test-RegistryValue $IEMain "NotifyDisableIEOptions" 0

$IEFeeds = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
Test-RegistryValue $IEFeeds "DisableEnclosureDownload" 1
Test-RegistryValue $IEFeeds "AllowBasicAuthInClear" 0

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Test-RegistryValue $SystemPath "DisableAutomaticRestartSignOn" 1
Test-RegistryValue $SystemPath "InactivityTimeoutSecs" 900
Test-RegistryValue $SystemPath "LegalNoticeCaption" "US Department of Defense Warning Statement"

$Installer = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
Test-RegistryValue $Installer "EnableUserControl" 0
Test-RegistryValue $Installer "AlwaysInstallElevated" 0
Test-RegistryValue $Installer "SafeForScripting" 0

$GameDVR = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
Test-RegistryValue $GameDVR "AllowGameDVR" 0

$InkWorkspace = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace"
Test-RegistryValue $InkWorkspace "AllowWindowsInkWorkspace" 1

$SessionMgr = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
Test-RegistryValue $SessionMgr "ProtectionMode" 1

$SecLogon = "HKLM:\SYSTEM\CurrentControlSet\Services\seclogon"
Test-RegistryValue $SecLogon "Start" 4

# ASLR and Speculative mitigations
$MemMgmt = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
Test-RegistryValue $MemMgmt "MoveImages" 4294967295
Test-RegistryValue $MemMgmt "FeatureSettingsOverride" 72
Test-RegistryValue $MemMgmt "FeatureSettingsOverrideMask" 3

# Strict Authenticode check
Test-RegistryValue "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" 1
Test-RegistryValue "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" 1

# Secure Batch processing
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" 1

# Disable Time-Travel Debugging
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\TTD" "RecordingPolicy" 2

# Prevent standard users from root cert installation
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" 1

# Disable AppInit_DLLs
Test-RegistryValue "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" 0

# Block driver co-installers
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" "DisableCoInstallers" 1

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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.2.1 (Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'), Section 18.8.3.1 (Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'), Section 18.8.21.1 (Ensure 'Always install with elevated privileges' is set to 'Disabled')
* **Microsoft Windows Security Baselines**: User configuration guidelines
* **DoD Windows 11 Computer STIG v2r6**: Various lock screen personalization, telemetry, Internet Explorer, Windows Installer, inactivity timeouts, and legal warning banner settings.
