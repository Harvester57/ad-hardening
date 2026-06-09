# Hardening Requirement: Enforce BitLocker with TPM and Startup PIN for PAWs

## Target Scope
* **Applicable Systems**: Tier 0 Privileged Access Workstations (PAWs).
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption
  * Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives
  * Computer Configuration\Administrative Templates\System\Power Management\Sleep Settings
  * Computer Configuration\Administrative Templates\System\Kernel DMA Protection
  * HKLM\SOFTWARE\Policies\Microsoft\FVE
  * HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc251b-215d-4f10-ae40-e226dbe3c6a3
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection

---

## Rationale
Privileged Access Workstations (PAWs) serve as the secure root of trust for administering Tier 0 Active Directory resources. Because these devices are physical endpoints, they are susceptible to theft, loss, and unauthorized physical access. 

To achieve maximum protection, the PAW BitLocker configuration enforces a significantly more stringent baseline than standard client endpoints:
1. **TPM and Startup PIN**: Enforcing a pre-boot Startup PIN combined with TPM validation ensures that the drive cannot be unlocked or booted without explicit administrator presence. Network Unlock is prohibited on PAWs to prevent automatic decryption when connected to a local switch, ensuring physical presence verification is mandatory for every boot.
2. **Disabling Sleep/Standby States (S1-S3)**: When a system enters a standby/sleep state, the BitLocker volume decryption keys remain stored in the volatile memory (RAM). An attacker with brief physical access to a sleeping PAW can exploit Direct Memory Access (DMA) interfaces (such as Thunderbolt, FireWire, or PCIe slots) or perform a cold-boot attack to extract the decryption keys directly from the RAM. Disabling S1-S3 standby states forces the system to either shut down (S5) or hibernate (S4), writing the RAM contents back to the encrypted disk and purging the keys from volatile memory.
3. **Kernel DMA Protection**: This blocks peripheral devices (Thunderbolt, PCIe) from initiating DMA requests unless the OS is fully booted, authorized, and running driver-level Input-Output Memory Management Unit (IOMMU) protection, preventing DMA memory extraction during the pre-boot and OS load phases.
4. **Enhanced Startup PINs**: This allows administrators to use alphanumeric characters, symbols, uppercase and lowercase letters, and spaces in their pre-boot Startup PIN rather than just numbers, increasing entropy and resistance to PIN-guessing attacks.
5. **Active Directory Backup & Recovery Password Rotation**: Ensures all BitLocker recovery keys are automatically backed up to Active Directory before encryption begins. In addition, when a recovery key is used to unlock a PAW, it must be automatically rotated and updated in Active Directory to prevent the reuse of compromised recovery keys.

---

## Legacy Impact & Compatibility
* **Administrator Overhead**: PAW administrators must enter the Startup PIN on every boot and every resume from hibernation.
* **Hibernation Support**: Hardware must support hibernation, and it must be enabled on the operating system (`powercfg /h on`).
* **Resume Time**: Waking the workstation from hibernation or cold boot takes slightly longer than resuming from standard standby sleep, but this latency is necessary to satisfy the Tier 0 threat model.
* **Hardware Pre-requisites**: A physical TPM 2.0 chip and motherboard support for Kernel DMA Protection (IOMMU) are required.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Enforce BitLocker Encryption Strength
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption`
4. Configure the following setting:
   * **Policy**: `Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)`
   * **Setting**: `Enabled`
   * **Select the encryption method**: `XTS-AES 256-bit` (for Operating System drives)

#### Step 2: Enforce TPM + Startup PIN and Enhanced PIN Policies
1. In the same GPO, navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives`
2. Configure the following settings:
   * **Policy**: `Require additional authentication at startup`
   * **Setting**: `Enabled`
   * **Configure Options**:
     * Set `Configure TPM startup`: `Require TPM`
     * Set `Configure TPM startup PIN`: `Require startup PIN with TPM`
     * Set `Configure TPM startup key`: `Do not allow startup key with TPM`
     * Set `Configure TPM startup key and PIN`: `Do not allow startup key and PIN with TPM`
     * Check `Allow BitLocker without a compatible TPM`: `Disabled`
   * **Policy**: `Configure use of enhanced PINs for startup`
   * **Setting**: `Enabled`
   * **Policy**: `Minimum PIN length for startup`
   * **Setting**: `Enabled`
   * **Minimum characters**: `8` (or higher depending on local organizational policy)

#### Step 3: Configure Active Directory Backup and Key Rotation
1. In the same OS Drives folder, configure the following settings:
   * **Policy**: `Choose how BitLocker-protected operating system drives can be recovered`
   * **Setting**: `Enabled`
   * **Configure Options**:
     * Check `Allow data recovery agent`
     * Check `Save BitLocker recovery information to Active Directory Domain Services`
     * Set `Configure user storage of BitLocker recovery information`: `Store recovery passwords and key packages`
     * Check `Do not enable BitLocker until recovery information is stored in AD DS for operating system drives`
   * **Policy**: `Configure recovery password rotation for AD DS-joined computers`
   * **Setting**: `Enabled`
   * **Rotation options**: `Must rotate the recovery password for OS drives and fixed data drives`

#### Step 4: Disable Sleep/Standby States (S1-S3)
1. In the GPO, navigate to:
   `Computer Configuration\Administrative Templates\System\Power Management\Sleep Settings`
2. Configure the following settings:
   * **Policy**: `Allow standby states (S1-S3) when sleeping (plugged in)`
   * **Setting**: `Disabled`
   * **Policy**: `Allow standby states (S1-S3) when sleeping (on battery)`
   * **Setting**: `Disabled`

#### Step 5: Enable Kernel DMA Protection
1. In the GPO, navigate to:
   `Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
2. Configure the following setting:
   * **Policy**: `Enable Kernel DMA Protection`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on the PAW to apply registry configuration baselines and enable BitLocker.

```powershell
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
```

*To audit the PAW BitLocker status and security parameters:*
```powershell
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
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R58 (Use of Privileged Access Workstations), Recommendation R9 (LAPS context for BitLocker recovery keys protection).
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1.1 (Require additional authentication at startup), Section 18.2.1.2 (Configure use of enhanced PINs for startup), Section 18.2.1.3 (Configure minimum PIN length for startup), Section 18.2.1.4 (Configure recovery password rotation).
* **Microsoft Security Guidelines**: Device Guard and DMA protection reference architecture guides.
