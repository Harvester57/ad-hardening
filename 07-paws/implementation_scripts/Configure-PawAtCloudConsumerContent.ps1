#Configure-PawAtCloudConsumerContent.ps1
# Description: Configures Administrative Templates: Disable Cloud Consumer Account State Content for PAWs.

Write-Host "Configuring Administrative Templates: Disable Cloud Consumer Account State Content for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cloud Consumer Account State Content for PAWs applied successfully." -ForegroundColor Green
