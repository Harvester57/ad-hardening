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

# Kernel-level Shadow Stacks
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" "Enabled" 1

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
