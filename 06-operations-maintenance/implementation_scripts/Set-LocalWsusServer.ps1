# Set-LocalWsusServer.ps1
# Description: Configures the local client registry to utilize the dedicated Tier 0 WSUS over HTTPS.

Write-Host "Applying hardening requirement: Configure Dedicated WSUS for Tier 0..." -ForegroundColor Cyan

$WsusRegPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
$WsusServerUrl = "https://wsust0.corp.local:8531"

if (-not (Test-Path $WsusRegPath)) {
    New-Item -Path $WsusRegPath -Force | Out-Null
}

# 1. Configure target WSUS server values
Set-ItemProperty -Path $WsusRegPath -Name "WUServer" -Value $WsusServerUrl -Type String -ErrorAction Stop
Set-ItemProperty -Path $WsusRegPath -Name "WUStatusServer" -Value $WsusServerUrl -Type String -ErrorAction Stop

# 2. Force Windows Update configuration to use local settings
$UpdateAuPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
if (-not (Test-Path $UpdateAuPath)) {
    New-Item -Path $UpdateAuPath -Force | Out-Null
}
Set-ItemProperty -Path $UpdateAuPath -Name "UseWUServer" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "[+] Local system configured to use secure WSUS server: $WsusServerUrl" -ForegroundColor Green
