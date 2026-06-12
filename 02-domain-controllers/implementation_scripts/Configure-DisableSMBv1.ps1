# Configure-DisableSMBv1.ps1
# Description: Disables SMBv1 server protocol and mrxsmb10 client driver.

Write-Host "Applying hardening requirement: Disable SMBv1..." -ForegroundColor Cyan

# 1. Disable SMBv1 Server
$srvRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $srvRegPath)) {
    New-Item -Path $srvRegPath -Force | Out-Null
}
Set-ItemProperty -Path $srvRegPath -Name "SMB1" -Value 0 -Type DWord
Write-Host "SMBv1 Server registry configuration applied." -ForegroundColor Green

# Use standard cmdlet if available
if (Get-Command -Name Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "SMBv1 Server protocol disabled via cmdlet." -ForegroundColor Green
}

# 2. Disable SMBv1 Client Driver
$clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if (Test-Path $clientRegPath) {
    Set-ItemProperty -Path $clientRegPath -Name "Start" -Value 4 -Type DWord
    Write-Host "SMBv1 Client mrxsmb10 driver disabled." -ForegroundColor Green
} else {
    Write-Host "mrxsmb10 driver registry key not found (may already be removed)." -ForegroundColor Yellow
}

Write-Host "Hardening applied successfully. A system reboot is required." -ForegroundColor Green
