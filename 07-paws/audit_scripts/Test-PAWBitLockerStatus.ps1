# Test-PAWBitLockerStatus.ps1
# Audits current BitLocker configuration, active protectors, sleep state, and DMA protection.

Write-Host "--- Auditing PAW BitLocker Security Parameters ---" -ForegroundColor Cyan

# 1. Query BitLocker protection and key protector types
$Volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($Volume) {
    $StatusColor = if ($Volume.ProtectionStatus -eq "On") { "Green" } else { "Red" }
    Write-Host "    - Protection Status: $($Volume.ProtectionStatus)" -ForegroundColor $StatusColor
    Write-Host "    - Encryption Method: $($Volume.EncryptionMethod)" -ForegroundColor White
    
    $HasTpmPin = $false
    foreach ($Protector in $Volume.KeyProtector) {
        if ($Protector.KeyProtectorType -eq "TpmAndPin") {
            $HasTpmPin = $true
        }
        Write-Host "    - Active Protector: $($Protector.KeyProtectorType)" -ForegroundColor White
    }
    
    if ($HasTpmPin) {
        Write-Host "    [+] TPM and Startup PIN is ACTIVE." -ForegroundColor Green
    } else {
        Write-Host "    [-] TPM and Startup PIN is MISSING." -ForegroundColor Red
    }
} else {
    Write-Error "BitLocker volume information could not be retrieved."
}

# 2. Check Sleep State S1-S3 status
$SleepVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc251b-215d-4f10-ae40-e226dbe3c6a3" -Name "ACSettingIndex" -ErrorAction SilentlyContinue
if ($SleepVal -and $SleepVal.ACSettingIndex -eq 0) {
    Write-Host "    [+] Standby Sleep States (S1-S3) are disabled." -ForegroundColor Green
} else {
    Write-Host "    [-] Standby Sleep States (S1-S3) are enabled (Risk of DMA attack)." -ForegroundColor Red
}

# 3. Check Kernel DMA Protection
$DmaVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection" -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
if ($DmaVal -and $DmaVal.DeviceEnumerationPolicy -eq 0) {
    Write-Host "    [+] Kernel DMA Protection is enabled." -ForegroundColor Green
} else {
    Write-Host "    [-] Kernel DMA Protection is disabled." -ForegroundColor Red
}
