# Set-PAWBitLockerEncryption.ps1
# Configures registry settings for PAW BitLocker, disables sleep states, and enables encryption.

Write-Host "--- Enforcing Stringent PAW BitLocker Baseline ---" -ForegroundColor Cyan

# 1. Enforce encryption strength (XTS-AES 256 = 7)
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $FvePath)) {
    New-Item -Path $FvePath -Force | Out-Null
}
Set-ItemProperty -Path $FvePath -Name "EncryptionMethodWithXtsOs" -Value 7 -Type DWord

# 2. Configure TPM + Startup PIN, AD Backup, and Enhanced PINs in registry
Set-ItemProperty -Path $FvePath -Name "UseAdvancedStartup" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "EnableNonTpm" -Value 0 -Type DWord
Set-ItemProperty -Path $FvePath -Name "UseTPM" -Value 2 -Type DWord # 2 = Require
Set-ItemProperty -Path $FvePath -Name "UseTPMPIN" -Value 2 -Type DWord # 2 = Require
Set-ItemProperty -Path $FvePath -Name "UseEnhancedPINs" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "MinPINLength" -Value 8 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSRecovery" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSRecoveryPassword" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSBackupSaveSource" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSActiveDirectoryBackup" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSRequireActiveDirectoryBackup" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "OSRecoveryPasswordRotation" -Value 1 -Type DWord # 1 = Enforce rotation

# 3. Disable Sleep States S1-S3 via GPO Registry override
$PowerSleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc251b-215d-4f10-ae40-e226dbe3c6a3"
if (-not (Test-Path $PowerSleepPath)) {
    New-Item -Path $PowerSleepPath -Force | Out-Null
}
Set-ItemProperty -Path $PowerSleepPath -Name "ACSettingIndex" -Value 0 -Type DWord
Set-ItemProperty -Path $PowerSleepPath -Name "DCSettingIndex" -Value 0 -Type DWord

# Enforce hibernate locally using powercfg
powercfg /hibernate on
Write-Host "[+] Sleep states S1-S3 disabled, and Hibernation enabled." -ForegroundColor Green

# 4. Enable Kernel DMA Protection in registry
$DmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $DmaPath)) {
    New-Item -Path $DmaPath -Force | Out-Null
}
Set-ItemProperty -Path $DmaPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "[+] Kernel DMA Protection registry configuration applied." -ForegroundColor Green

# 5. Enable BitLocker on C: drive using TPM and Startup PIN
$Volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($Volume.ProtectionStatus -eq "Off") {
    Write-Host "[+] Activating BitLocker on C: volume..." -ForegroundColor Gray
    
    # We must first define a temporary PIN to enable startup PIN protection programmatically
    # The administrator must change this PIN immediately on next reboot
    $SecurePin = ConvertTo-SecureString "P@ssw0rdPIN1" -AsPlainText -Force
    
    Enable-BitLocker -MountPoint "C:" `
        -EncryptionMethod XtsAes256 `
        -UsedSpaceOnly `
        -Pin $SecurePin `
        -TpmAndPinProtector `
        -AdBackupRequired
        
    Write-Host "[+] BitLocker initiated with TPM and Startup PIN. Recovery keys sent to AD." -ForegroundColor Green
} else {
    Write-Host "[+] BitLocker is already enabled on C: (Protection Status: $($Volume.ProtectionStatus))." -ForegroundColor Green
}
