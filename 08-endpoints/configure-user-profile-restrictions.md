# Hardening Requirement: Configure User Profile Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications
    * User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content
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

---

## Rationale
Securing user profile characteristics and administrative explorer behaviors prevents exposure of sensitive information, restricts arbitrary file execution pathways, disables unapproved telemetry/consumer features, and locks down potential privilege escalation points:

1. **Lock Screen Toast Notifications (`NoToastApplicationNotificationOnLockScreen`)**: By default, Windows displays application notifications (toasts) on the lock screen. This includes email snippets, messaging notifications, or Multi-Factor Authentication (MFA) codes. If a workstation is left locked, anyone with physical sight of the screen can read these notifications, leaking corporate secrets or bypassing authentication challenges. Disabling these toasts on the lock screen prevents this exposure.
2. **Third-Party Consumer Experiences (`DisableThirdPartySuggestions` & `DisableWindowsConsumerFeatures`)**: Windows Spotlight frequently recommends third-party software, applications, or advertising on the lock screen and Start menu. Disabling third-party content prevents telemetry generation, unapproved software installation prompts, and social-engineering entry points.
3. **Shell Context Menu runasuser Bypass (`SuppressionPolicy`)**: Restricting the "Run as different user" shell context menus prevents standard users from attempting to launch executables under different identities without triggering formal security validation or UAC controls.
4. **Kernel SEHOP (`DisableExceptionChainValidation`)**: Structured Exception Handler Overwrite Protection (SEHOP) detects and blocks stack-based buffer overflow exploit redirection techniques at the OS level.
5. **Explorer and Installer Hardening (`AlwaysInstallElevated`, `EnableUserControl`)**: Forcing standard user installer locks and disabling elevated installations prevents users from escalating privileges using crafted installer files.
6. **Inactivity Timeout (`InactivityTimeoutSecs`)**: Automatically locking idle workstations after 15 minutes of inactivity (900 seconds) prevents physical session hijacking.

---

## Legacy Impact & Compatibility
* **User Notifications**: Users will still receive notifications while logged in and unlocked. However, when the workstation is locked, they will only see system status indicators, not detailed content banners.
* **Spotlight Aesthetics**: The lock screen background can still show administrative wallpaper choices, but will not query online Microsoft consumer recommendations.
* **Installer Failures**: Administrators will need to perform standard GPO-based software distribution or elevate installers manually, since "AlwaysInstallElevated" is securely disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To apply user configuration settings, link the GPO to OUs containing user accounts (or enable GPO Loopback Processing on the computer policy).

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the appropriate endpoint GPO (e.g., `GPO_Hardening_UserProfile_Restrictions`).
3. Configure the following settings:

#### 1. User Configuration
Navigate to: `User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications`
* **Policy**: `Turn off toast notifications on the lock screen` -> Set to **Enabled**

Navigate to: `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content`
* **Policy**: `Do not suggest third-party content in Windows spotlight` -> Set to **Enabled**

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

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure user and system registry restrictions.

[Download Script: Set-UserProfileRestrictions.ps1](implementation_scripts/Set-UserProfileRestrictions.ps1)

```powershell
# Set-UserProfileRestrictions.ps1
# Description: Configures HKLM and HKCU registry settings for user profiles, shell behaviors, diagnostic data, installer locks, inactivity timeouts, and security policies.

Write-Host "Applying User Profile and System Restrictions..." -ForegroundColor Cyan

# Helper function to create keys and set values safely
function Set-RegDWord ($path, $name, $value) {
    $parent = Split-Path -Path $path
    if (-not (Test-Path $parent)) {
        New-Item -Path $parent -Force | Out-Null
    }
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
}

function Set-RegString ($path, $name, $value) {
    $parent = Split-Path -Path $path
    if (-not (Test-Path $parent)) {
        New-Item -Path $parent -Force | Out-Null
    }
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force
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

Write-Host "[+] Local computer system restrictions applied." -ForegroundColor Green

# 2. Enforce HKCU Settings on Current User
$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"

if (-not (Test-Path $PushPath)) {
    New-Item -Path $PushPath -Force | Out-Null
}
Set-ItemProperty -Path $PushPath -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord

if (-not (Test-Path $CloudPath)) {
    New-Item -Path $CloudPath -Force | Out-Null
}
Set-ItemProperty -Path $CloudPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
Write-Host "[+] Current user profile restrictions applied successfully." -ForegroundColor Green

# 3. Enforce HKCU Settings on Default User Hive (For all future user profiles on this machine)
Write-Host "[*] Configuring Default User profile registry keys..." -ForegroundColor Gray
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"

if (Test-Path $DefaultHivePath) {
    # Load default hive
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    
    $DefaultPush = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $DefaultCloud = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    
    if (-not (Test-Path $DefaultPush)) {
        New-Item -Path $DefaultPush -Force | Out-Null
    }
    Set-ItemProperty -Path $DefaultPush -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord
    
    if (-not (Test-Path $DefaultCloud)) {
        New-Item -Path $DefaultCloud -Force | Out-Null
    }
    Set-ItemProperty -Path $DefaultCloud -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
    
    # Unload default hive
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
    
    Write-Host "[+] Default User registry template updated successfully." -ForegroundColor Green
} else {
    Write-Warning "Default User hive NTUSER.DAT not found."
}
```

*To audit local user profile configuration:*
[Download Script: Test-UserProfileRestrictions.ps1](audit_scripts/Test-UserProfileRestrictions.ps1)

```powershell
# Test-UserProfileRestrictions.ps1
# Description: Checks HKCU and HKLM registry settings for active user and system profile restrictions.

Write-Host "--- Auditing User Profile Restrictions ---" -ForegroundColor Cyan

$Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue ($path, $name, $expectedValue) {
    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    $color = "Red"
    if ($actual -eq $expectedValue) {
        $color = "Green"
    } else {
        $global:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expectedValue')" -ForegroundColor $color
}

# 1. Audit Current User Settings
$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
Test-RegistryValue $PushPath "NoToastApplicationNotificationOnLockScreen" 1
Test-RegistryValue $CloudPath "DisableThirdPartySuggestions" 1

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

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.2.1 (Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'), Section 18.8.3.1 (Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'), Section 18.8.21.1 (Ensure 'Always install with elevated privileges' is set to 'Disabled')
* **Microsoft Windows Security Baselines**: User configuration guidelines
* **DoD Windows 11 Computer STIG v2r6**: Various lock screen personalization, telemetry, Internet Explorer, Windows Installer, inactivity timeouts, and legal warning banner settings.

