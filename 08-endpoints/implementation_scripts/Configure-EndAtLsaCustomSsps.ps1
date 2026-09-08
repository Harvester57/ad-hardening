#Configure-EndAtLsaCustomSsps.ps1
# Description: Configures Administrative Templates: Block Custom SSPs and APs from Loading into LSASS.

Write-Host "Configuring Administrative Templates: Block Custom SSPs and APs from Loading into LSASS..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowCustomSSPsAPs" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Block Custom SSPs and APs from Loading into LSASS applied successfully." -ForegroundColor Green
