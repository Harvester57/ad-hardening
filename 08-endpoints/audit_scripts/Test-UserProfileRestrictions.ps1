# Test-UserProfileRestrictions.ps1
# Description: Checks HKCU and HKLM registry settings for active user and system profile restrictions.

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
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
