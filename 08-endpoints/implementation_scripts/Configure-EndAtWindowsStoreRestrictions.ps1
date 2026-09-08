#Configure-EndAtWindowsStoreRestrictions.ps1
# Description: Configures Administrative Templates: Windows Store Updates and OS Upgrade Restrictions.

Write-Host "Configuring Administrative Templates: Windows Store Updates and OS Upgrade Restrictions..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 4 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Store Updates and OS Upgrade Restrictions applied successfully." -ForegroundColor Green
