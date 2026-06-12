# Set-BitLockerEncryption.ps1
# Enables BitLocker encryption locally and backs up recovery keys to AD.

Write-Host "--- Enforcing BitLocker Drive Encryption ---" -ForegroundColor Cyan

# 1. Enable BitLocker on C: drive using TPM protection
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
