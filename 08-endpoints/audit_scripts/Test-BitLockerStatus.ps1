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
$FveSysPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"

$Params = @(
    @{ Name = "AllowNetworkUnlock"; Expected = 1; Path = $FveRegPath },
    @{ Name = "MinimumPIN"; Expected = 6; Path = $FveRegPath },
    @{ Name = "UseTPM"; Expected = 2; Path = $FveRegPath },
    @{ Name = "UseTPMPIN"; Expected = 2; Path = $FveRegPath },
    @{ Name = "UseTPMKey"; Expected = 2; Path = $FveRegPath },
    @{ Name = "UseTPMKeyPIN"; Expected = 2; Path = $FveRegPath },
    
    # OS Drives
    @{ Name = "UseEnhancedPin"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSAllowSecureBootForIntegrity"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSRecovery"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSManageDRA"; Expected = 0; Path = $FveRegPath },
    @{ Name = "OSRecoveryPassword"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSRecoveryKey"; Expected = 0; Path = $FveRegPath },
    @{ Name = "OSHideRecoveryPage"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSActiveDirectoryBackup"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSActiveDirectoryInfoToStore"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSRequireActiveDirectoryBackup"; Expected = 1; Path = $FveRegPath },
    @{ Name = "OSHardwareEncryption"; Expected = 0; Path = $FveRegPath },
    @{ Name = "OSPassphrase"; Expected = 0; Path = $FveRegPath },
    @{ Name = "UseAdvancedStartup"; Expected = 1; Path = $FveRegPath },
    @{ Name = "EnableBDEWithNoTPM"; Expected = 0; Path = $FveRegPath },
    
    # Fixed Drives
    @{ Name = "FDVDiscoveryVolumeType"; Expected = ""; Path = $FveRegPath },
    @{ Name = "FDVRecovery"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVManageDRA"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVRecoveryPassword"; Expected = 2; Path = $FveRegPath },
    @{ Name = "FDVRecoveryKey"; Expected = 2; Path = $FveRegPath },
    @{ Name = "FDVHideRecoveryPage"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVActiveDirectoryBackup"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVActiveDirectoryInfoToStore"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVRequireActiveDirectoryBackup"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVHardwareEncryption"; Expected = 0; Path = $FveRegPath },
    @{ Name = "FDVPassphrase"; Expected = 0; Path = $FveRegPath },
    @{ Name = "FDVAllowUserCert"; Expected = 1; Path = $FveRegPath },
    @{ Name = "FDVEnforceUserCert"; Expected = 1; Path = $FveRegPath },
    
    # Removable Drives
    @{ Name = "RDVDiscoveryVolumeType"; Expected = ""; Path = $FveRegPath },
    @{ Name = "RDVRecovery"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVManageDRA"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVRecoveryPassword"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVRecoveryKey"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVHideRecoveryPage"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVActiveDirectoryBackup"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVActiveDirectoryInfoToStore"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVRequireActiveDirectoryBackup"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVHardwareEncryption"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVPassphrase"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVAllowUserCert"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVEnforceUserCert"; Expected = 1; Path = $FveRegPath },
    @{ Name = "RDVDenyCrossOrg"; Expected = 0; Path = $FveRegPath },
    @{ Name = "RDVDenyWriteAccess"; Expected = 1; Path = $FveSysPath }
)

Write-Host "`n[*] Auditing BitLocker settings:" -ForegroundColor Yellow
$script:Vulnerable = $false

foreach ($Param in $Params) {
    if (Test-Path $Param.Path) {
        $Val = Get-ItemProperty -Path $Param.Path -Name $Param.Name -ErrorAction SilentlyContinue
        $ActualVal = if ($Val) { $Val.$($Param.Name) } else { $null }
        
        $IsMatch = $false
        if ($Param.Expected -eq "") {
            $IsMatch = ($null -eq $ActualVal -or $ActualVal -eq "")
        } else {
            $IsMatch = ($ActualVal -eq $Param.Expected)
        }
        
        $Color = if ($IsMatch) { "Green" } else { "Red" }
        if (-not $IsMatch) { $script:Vulnerable = $true }
        
        Write-Host "    - $($Param.Name): $ActualVal (Expected = $($Param.Expected))" -ForegroundColor $Color
    } else {
        Write-Host "    - Policy key $($Param.Path) does not exist." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
