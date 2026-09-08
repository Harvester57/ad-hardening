#Configure-EndAtRemoteAssistance.ps1
# Description: Configures Administrative Templates: Disable Remote Assistance.

Write-Host "Configuring Administrative Templates: Disable Remote Assistance..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Remote Assistance applied successfully." -ForegroundColor Green
