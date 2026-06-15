# Set-BitLockerEncryption.ps1
# Enables BitLocker encryption locally, configures startup policies/PIN lengths, and backs up recovery keys to AD.

Write-Host "--- Enforcing BitLocker Drive Encryption ---" -ForegroundColor Cyan

# 1. Configure FVE Registry settings
$FveRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $FveRegPath)) {
    New-Item -Path $FveRegPath -Force | Out-Null
}

# General Startup and Network Unlock settings
Set-ItemProperty -Path $FveRegPath -Name "AllowNetworkUnlock" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "MinimumPIN" -Value 6 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPM" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMPIN" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMKey" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseTPMKeyPIN" -Value 2 -Type DWord -Force

# OS Drive Settings (18.10.10.2.x)
Set-ItemProperty -Path $FveRegPath -Name "UseEnhancedPin" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSAllowSecureBootForIntegrity" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSRecovery" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSManageDRA" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSRecoveryPassword" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSRecoveryKey" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSHideRecoveryPage" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSActiveDirectoryBackup" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSActiveDirectoryInfoToStore" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSRequireActiveDirectoryBackup" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSHardwareEncryption" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "OSPassphrase" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "UseAdvancedStartup" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "EnableBDEWithNoTPM" -Value 0 -Type DWord -Force

# Fixed Drive Settings (18.10.10.1.x)
Set-ItemProperty -Path $FveRegPath -Name "FDVDiscoveryVolumeType" -Value "" -Type String -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVRecovery" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVManageDRA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVRecoveryPassword" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVRecoveryKey" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVHideRecoveryPage" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVActiveDirectoryBackup" -Value 1 -Type DWord -Force  # Overridden to enable AD backups
Set-ItemProperty -Path $FveRegPath -Name "FDVActiveDirectoryInfoToStore" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVRequireActiveDirectoryBackup" -Value 1 -Type DWord -Force  # Overridden to require AD backups
Set-ItemProperty -Path $FveRegPath -Name "FDVHardwareEncryption" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVPassphrase" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVAllowUserCert" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "FDVEnforceUserCert" -Value 1 -Type DWord -Force

# Removable Drive Settings (18.10.10.3.x)
Set-ItemProperty -Path $FveRegPath -Name "RDVDiscoveryVolumeType" -Value "" -Type String -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVRecovery" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVManageDRA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVRecoveryPassword" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVRecoveryKey" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVHideRecoveryPage" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVActiveDirectoryBackup" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVActiveDirectoryInfoToStore" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVRequireActiveDirectoryBackup" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVHardwareEncryption" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVPassphrase" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVAllowUserCert" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVEnforceUserCert" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $FveRegPath -Name "RDVDenyCrossOrg" -Value 0 -Type DWord -Force

# Removable Drive Write Blocks (System FVE Policies)
$FveSystemPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
if (-not (Test-Path $FveSystemPath)) {
    New-Item -Path $FveSystemPath -Force | Out-Null
}
Set-ItemProperty -Path $FveSystemPath -Name "RDVDenyWriteAccess" -Value 1 -Type DWord -Force

Write-Host "[+] BitLocker startup authentication and volume encryption policies configured." -ForegroundColor Green

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
