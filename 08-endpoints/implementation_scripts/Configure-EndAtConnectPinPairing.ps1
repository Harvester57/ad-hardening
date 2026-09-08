#Configure-EndAtConnectPinPairing.ps1
# Description: Configures Administrative Templates: Require PIN for Connect Wireless Pairing.

Write-Host "Configuring Administrative Templates: Require PIN for Connect Wireless Pairing..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Require PIN for Connect Wireless Pairing applied successfully." -ForegroundColor Green
