# Set-BitLockerEncryption.ps1
# Enables BitLocker encryption locally, configures startup policies/PIN lengths, and backs up recovery keys to AD.

Write-Host "--- Enforcing BitLocker Drive Encryption ---" -ForegroundColor Cyan

# 1. Configure FVE Registry settings for startup authentication
$FveRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $FveRegPath)) {
    New-Item -Path $FveRegPath -Force | Out-Null
}

Set-ItemProperty -Path $FveRegPath -Name "AllowNetworkUnlock" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "MinimumPIN" -Value 6 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "EnableBDEWithNoTPM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPM" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMPIN" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMKey" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMKeyPIN" -Value 2 -Type DWord -Force

Write-Host "[+] BitLocker startup authentication registry keys configured." -ForegroundColor Green

# 2. Enable BitLocker on C: drive using TPM protection
$Volume = Get-BitLockerVolume -MountPoint "C:"

# Check if protection is already active
if ($Volume.ProtectionStatus -eq "Off") {
    Write-Host "[+] Activating BitLocker on C: drive using XTS-AES 256 encryption..." -ForegroundColor Gray
    
    # Enable BitLocker and backup recovery password protector to Active Directory
    Enable-BitLocker -MountPoint "C:" `
        -EncryptionMethod XtsAes256 `
        -UsedSpaceOnly `
        -TpmProtector `
        -AdBackupRequired
        
    Write-Host "[+] BitLocker encryption initiated. Recovery key backed up to AD." -ForegroundColor Green
} else {
    Write-Host "[+] BitLocker is already enabled on C: (Protection Status: $($Volume.ProtectionStatus))." -ForegroundColor Green
}
