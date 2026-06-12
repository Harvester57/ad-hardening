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
