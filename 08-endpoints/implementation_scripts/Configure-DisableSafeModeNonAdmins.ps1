# Configure-DisableSafeModeNonAdmins.ps1
# Description: Prevents standard users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "SafeModeBlockNonAdmins"
$ValueData = 1

Write-Host "Applying hardening requirement: Restrict Safe Mode access to administrators..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force | Out-Null
Write-Host "Hardening applied successfully." -ForegroundColor Green
