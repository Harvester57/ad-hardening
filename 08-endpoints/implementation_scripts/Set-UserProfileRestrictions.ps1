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
