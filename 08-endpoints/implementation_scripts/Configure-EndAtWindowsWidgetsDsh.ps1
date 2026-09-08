#Configure-EndAtWindowsWidgetsDsh.ps1
# Description: Configures Administrative Templates: Disable Windows Widgets and News Feed.

Write-Host "Configuring Administrative Templates: Disable Windows Widgets and News Feed..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Widgets and News Feed applied successfully." -ForegroundColor Green
