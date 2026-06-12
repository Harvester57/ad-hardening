# Test-BitLockerStatus.ps1
# Audits current BitLocker protection state, key protector types, and Network Unlock configuration.

Write-Host "--- Auditing BitLocker Status ---" -ForegroundColor Cyan

# 1. Query local BitLocker state
$Volume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($Volume) {
    $StatusColor = if ($Volume.ProtectionStatus -eq "On") { "Green" } else { "Red" }
    Write-Host "    - Protection Status: $($Volume.ProtectionStatus)" -ForegroundColor $StatusColor
    Write-Host "    - Encryption Method: $($Volume.EncryptionMethod)" -ForegroundColor White
    
    Write-Host "`n[+] Active Key Protectors:" -ForegroundColor Yellow
    foreach ($Protector in $Volume.KeyProtector) {
        Write-Host "    - Type: $($Protector.KeyProtectorType) | ID: $($Protector.KeyProtectorId)" -ForegroundColor White
    }
} else {
    Write-Error "BitLocker volume information could not be retrieved."
}

# 2. Check Network Unlock registry configuration
$FveRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$NetUnlockVal = Get-ItemProperty -Path $FveRegPath -Name "AllowNetworkUnlock" -ErrorAction SilentlyContinue
$NetUnlockSetting = if ($NetUnlockVal) { $NetUnlockVal.AllowNetworkUnlock } else { 0 }
$NetColor = if ($NetUnlockSetting -eq 1) { "Green" } else { "Yellow" }
Write-Host "`n    - AllowNetworkUnlock Registry Value: $NetUnlockSetting (Required = 1 if using Network Unlock)" -ForegroundColor $NetColor
