# Test-BitLockerStatus.ps1
# Audits current BitLocker protection state, key protector types, and Network Unlock/Startup PIN configuration.

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

# 2. Check Network Unlock and Startup Authentication registry configuration
$FveRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$Params = @(
    @{ Name = "AllowNetworkUnlock"; Expected = 1 },
    @{ Name = "MinimumPIN"; Expected = 6 },
    @{ Name = "EnableBDEWithNoTPM"; Expected = 1 },
    @{ Name = "UseTPM"; Expected = 2 },
    @{ Name = "UseTPMPIN"; Expected = 2 },
    @{ Name = "UseTPMKey"; Expected = 2 },
    @{ Name = "UseTPMKeyPIN"; Expected = 2 }
)

Write-Host "`n[*] Auditing Startup Authentication & PIN parameters:" -ForegroundColor Yellow
if (Test-Path $FveRegPath) {
    foreach ($Param in $Params) {
        $Val = Get-ItemProperty -Path $FveRegPath -Name $Param.Name -ErrorAction SilentlyContinue
        $ActualVal = if ($Val) { $Val.$($Param.Name) } else { $null }
        $Color = if ($ActualVal -eq $Param.Expected) { "Green" } else { "Red" }
        Write-Host "    - $($Param.Name): $ActualVal (Expected = $($Param.Expected))" -ForegroundColor $Color
    }
} else {
    Write-Host "    - FVE Registry Policies key does not exist." -ForegroundColor Red
}
