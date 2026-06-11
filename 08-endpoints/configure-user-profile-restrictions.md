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
  * **Registry Locations**:
    * HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications
      * `NoToastApplicationNotificationOnLockScreen` = `1` (REG_DWORD)
    * HKCU\Software\Policies\Microsoft\Windows\CloudContent
      * `DisableThirdPartySuggestions` = `1` (REG_DWORD)

---

## Rationale
Securing user profile characteristics prevents exposure of sensitive information and blocks unapproved telemetry/consumer features:

1. **Lock Screen Toast Notifications (`NoToastApplicationNotificationOnLockScreen`)**: By default, Windows displays application notifications (toasts) on the lock screen. This includes email snippets, messaging notifications, or Multi-Factor Authentication (MFA) codes. If a workstation is left locked, anyone with physical sight of the screen can read these notifications, leaking corporate secrets or bypassing authentication challenges. Disabling these toasts on the lock screen prevents this exposure.
2. **Third-Party Consumer Experiences (`DisableThirdPartySuggestions`)**: Windows Spotlight frequently recommends third-party software, applications, or advertising on the lock screen and Start menu. Disabling third-party content prevents telemetry generation, unapproved software installation prompts, and social-engineering entry points.

---

## Legacy Impact & Compatibility
* **User Notifications**: Users will still receive notifications while logged in and unlocked. However, when the workstation is locked, they will only see system status indicators, not detailed content banners.
* **Spotlight Aesthetics**: The lock screen background can still show administrative wallpaper choices, but will not query online Microsoft consumer recommendations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To apply user configuration settings, ensure they are linked to the OUs containing user accounts (not computer accounts), or enable Loopback Processing on the computer GPO.

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting the User accounts OU (e.g., `GPO_Hardening_UserProfile_Restrictions`).
3. Configure the following settings under **User Configuration**:

#### 1. Turn Off Lock Screen Toasts
Navigate to:
`User Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Notifications`
* **Policy**: `Turn off toast notifications on the lock screen`
* **Setting**: `Enabled`

#### 2. Disable Cloud Spotlight Suggestions
Navigate to:
`User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content`
* **Policy**: `Do not suggest third-party content in Windows spotlight`
* **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Since user configurations reside in `HKEY_CURRENT_USER` (HKCU), remediation scripts must run in the context of the logged-on user. To apply these configurations machine-wide for all future profiles, the script can load the Default User hive (`NTUSER.DAT`) and apply the keys.

```powershell
# Set-UserProfileRestrictions.ps1
# Description: Configures HKCU registry parameters for the active user, and sets them in the Default User hive for new profiles.

Write-Host "Applying User Profile Restrictions..." -ForegroundColor Cyan

$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"

# 1. Enforce on Current User
if (-not (Test-Path $PushPath)) {
    New-Item -Path $PushPath -Force | Out-Null
}
Set-ItemProperty -Path $PushPath -Name "NoToastApplicationNotificationOnLockScreen" -Value 1 -Type DWord

if (-not (Test-Path $CloudPath)) {
    New-Item -Path $CloudPath -Force | Out-Null
}
Set-ItemProperty -Path $CloudPath -Name "DisableThirdPartySuggestions" -Value 1 -Type DWord
Write-Host "[+] Current user profile restrictions applied successfully." -ForegroundColor Green

# 2. Enforce on Default User Hive (For all future user profiles on this machine)
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
```powershell
# Test-UserProfileRestrictions.ps1
# Description: Checks the HKCU registry settings of the active user for profile restrictions.

Write-Host "--- Auditing User Profile Restrictions ---" -ForegroundColor Cyan

$PushPath = "HKCU:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$CloudPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"

$Toast = Get-ItemProperty -Path $PushPath -Name "NoToastApplicationNotificationOnLockScreen" -ErrorAction SilentlyContinue
$Spotlight = Get-ItemProperty -Path $CloudPath -Name "DisableThirdPartySuggestions" -ErrorAction SilentlyContinue

$ToastVal = if ($Toast) { $Toast.NoToastApplicationNotificationOnLockScreen } else { 0 }
$SpotlightVal = if ($Spotlight) { $Spotlight.DisableThirdPartySuggestions } else { 0 }

$ToastColor = if ($ToastVal -eq 1) { "Green" } else { "Red" }
$SpotlightColor = if ($SpotlightVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Turn Off Toast Notifications on Lock Screen: $ToastVal (Required = 1)" -ForegroundColor $ToastColor
Write-Host "    - Disable Spotlight Suggestions: $SpotlightVal (Required = 1)" -ForegroundColor $SpotlightColor
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.2.1 (Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'), Section 18.8.3.1 (Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled')
* **Microsoft Windows Security Baselines**: User configuration guidelines
