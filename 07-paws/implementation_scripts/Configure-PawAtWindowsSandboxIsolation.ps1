#Configure-PawAtWindowsSandboxIsolation.ps1
# Description: Configures Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs.

Write-Host "Configuring Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowClipboardRedirection" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" -Name "AllowNetworking" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Windows Sandbox Clipboard and Network Isolation for PAWs applied successfully." -ForegroundColor Green
