# Configure-SMBSigning.ps1
# Description: Enforces SMB signing for both SMB server and client.

Write-Host "Applying hardening requirement: Enforce SMB Message Signing..." -ForegroundColor Cyan

# 1. Enforce Server SMB Signing
$srvRegPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $srvRegPath)) {
    New-Item -Path $srvRegPath -Force | Out-Null
}
Set-ItemProperty -Path $srvRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
Write-Host "SMB Server signing (always) enabled." -ForegroundColor Green

# 2. Enforce Client SMB Signing
$cliRegPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $cliRegPath)) {
    New-Item -Path $cliRegPath -Force | Out-Null
}
Set-ItemProperty -Path $cliRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
Write-Host "SMB Client signing (always) enabled." -ForegroundColor Green
