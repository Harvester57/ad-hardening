#Configure-EndAtCrossDeviceExperiences.ps1
# Description: Configures Administrative Templates: Disable Cross-Device Experiences.

Write-Host "Configuring Administrative Templates: Disable Cross-Device Experiences..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cross-Device Experiences applied successfully." -ForegroundColor Green
