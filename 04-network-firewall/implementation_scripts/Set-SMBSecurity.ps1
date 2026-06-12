# Set-SMBSecurity.ps1
# Description: Disables SMBv1, mandates signing, sets SMBv3 as minimum dialect, and enforces encryption.

Write-Host "Enforcing SMBv3 security settings..." -ForegroundColor Cyan

# 1. Disable SMBv1 Protocol globally (Server side)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false | Out-Null
Write-Host "SMBv1 server protocol disabled." -ForegroundColor Green

# 2. Disable SMBv1 Driver (Windows Optional Feature)
$SMB1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($null -ne $SMB1Feature -and $SMB1Feature.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Write-Host "SMB1 optional feature disabled." -ForegroundColor Green
}

# 3. Configure SMB Signing & Encryption on Server
Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Confirm:$false | Out-Null
Write-Host "SMB Server signing and encryption mandated." -ForegroundColor Green

# 4. Configure SMB Signing & Encryption on Client
Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false | Out-Null
Write-Host "SMB Client signing mandated." -ForegroundColor Green

# 5. Enforce Minimum Dialects in Registry (Server and Client)
$ServerParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$ClientParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

# Write minimum dialect version 0x00000300 (SMB 3.0.0)
if (-not (Test-Path $ServerParamsPath)) {
    New-Item -Path $ServerParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $ServerParamsPath -Name "MinSMB2Dialect" -Value 0x00000300 -Type DWord -Force | Out-Null

if (-not (Test-Path $ClientParamsPath)) {
    New-Item -Path $ClientParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientParamsPath -Name "MinSMB2Dialect" -Value 0x00000300 -Type DWord -Force | Out-Null

# Disable legacy fallback protocols (e.g. NetBIOS over TCP/IP) if possible, but keep focus on SMBv3
Write-Host "SMBv3 minimum dialect rules configured." -ForegroundColor Green
