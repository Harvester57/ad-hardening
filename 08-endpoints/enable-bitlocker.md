# [REQ-END-012] Enable BitLocker and Network Unlock

## Target Scope
* **Applicable Systems**: Tier 2 client workstations.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption` (General and OS, Fixed, and Removable subkeys)
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies\BitLocker Network Unlock`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Policies\Microsoft\FVE` (General Startup & Encryption Policies)
      * `AllowNetworkUnlock` = `1` (REG_DWORD)
      * `MinimumPIN` = `6` (REG_DWORD)
      * `UseEnhancedPin` = `1` (REG_DWORD)
      * `UseTPM` = `2` (REG_DWORD)
      * `UseTPMPIN` = `2` (REG_DWORD)
      * `UseTPMKey` = `2` (REG_DWORD)
      * `UseTPMKeyPIN` = `2` (REG_DWORD)
      * `UseAdvancedStartup` = `1` (REG_DWORD)
      * `EnableBDEWithNoTPM` = `0` (REG_DWORD, Enforce TPM)
    * `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Operating System Drives `OS...` keys)
      * `OSAllowSecureBootForIntegrity` = `1` (REG_DWORD)
      * `OSRecovery` = `1` (REG_DWORD)
      * `OSManageDRA` = `0` (REG_DWORD)
      * `OSRecoveryPassword` = `1` (REG_DWORD, Require 48-digit)
      * `OSRecoveryKey` = `0` (REG_DWORD, Do not allow)
      * `OSHideRecoveryPage` = `1` (REG_DWORD)
      * `OSActiveDirectoryBackup` = `1` (REG_DWORD)
      * `OSActiveDirectoryInfoToStore` = `1` (REG_DWORD)
      * `OSRequireActiveDirectoryBackup` = `1` (REG_DWORD)
      * `OSHardwareEncryption` = `0` (REG_DWORD, Disable hardware encryption)
      * `OSPassphrase` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Fixed Data Drives `FDV...` keys)
      * `FDVDiscoveryVolumeType` = `""` (REG_SZ, blank string)
      * `FDVRecovery` = `1` (REG_DWORD)
      * `FDVManageDRA` = `1` (REG_DWORD)
      * `FDVRecoveryPassword` = `2` (REG_DWORD, Allow 48-digit)
      * `FDVRecoveryKey` = `2` (REG_DWORD, Allow 256-bit)
      * `FDVHideRecoveryPage` = `1` (REG_DWORD)
      * `FDVActiveDirectoryBackup` = `1` (REG_DWORD, Backup to AD DS enabled)
      * `FDVActiveDirectoryInfoToStore` = `1` (REG_DWORD)
      * `FDVRequireActiveDirectoryBackup` = `1` (REG_DWORD, Require AD backup)
      * `FDVHardwareEncryption` = `0` (REG_DWORD, Disable hardware encryption)
      * `FDVPassphrase` = `0` (REG_DWORD)
      * `FDVAllowUserCert` = `1` (REG_DWORD)
      * `FDVEnforceUserCert` = `1` (REG_DWORD, Require smart cards)
    * `HKLM\SOFTWARE\Policies\Microsoft\FVE` (Removable Data Drives `RDV...` keys)
      * `RDVDiscoveryVolumeType` = `""` (REG_SZ, blank string)
      * `RDVRecovery` = `1` (REG_DWORD)
      * `RDVManageDRA` = `1` (REG_DWORD)
      * `RDVRecoveryPassword` = `0` (REG_DWORD, Do not allow)
      * `RDVRecoveryKey` = `0` (REG_DWORD, Do not allow)
      * `RDVHideRecoveryPage` = `1` (REG_DWORD)
      * `RDVActiveDirectoryBackup` = `0` (REG_DWORD)
      * `RDVActiveDirectoryInfoToStore` = `1` (REG_DWORD)
      * `RDVRequireActiveDirectoryBackup` = `0` (REG_DWORD)
      * `RDVHardwareEncryption` = `0` (REG_DWORD)
      * `RDVPassphrase` = `0` (REG_DWORD)
      * `RDVAllowUserCert` = `1` (REG_DWORD)
      * `RDVEnforceUserCert` = `1` (REG_DWORD)
      * `RDVDenyCrossOrg` = `0` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Policies\Microsoft\FVE`
      * `RDVDenyWriteAccess` = `1` (REG_DWORD)

---

## Rationale
BitLocker Drive Encryption protects the operating system volume from offline attacks, data tampering, and data theft when the device is powered off or stolen. Without full disk encryption, an attacker with physical access to a workstation can extract the hard drive, mount it on a non-secure system, bypass operating system security controls, dump local password databases (SAM), and access cached domain credentials.

Enforcing specific BitLocker startup parameters, such as a minimum PIN length of at least 6 characters, ensures that if a startup PIN is used, it cannot be easily brute-forced. Restricting how the TPM, startup keys, and PINs are configured ensures consistent security policy application.

To maximize security, standard endpoints (Tier 2) should use **BitLocker Network Unlock** to prevent operational overhead in managing startup PINs for thousands of workstations. 

### How BitLocker Network Unlock Works
BitLocker Network Unlock allows domain-joined workstations connected to the wired corporate LAN to automatically unlock their OS drives on reboot, while still requiring a backup PIN or recovery key when disconnected from the corporate network.

```text
[Client PC Boot (UEFI)]
  |
  +-- Sends DHCP Request + Encrypted Key Payload (via Wired Ethernet)
        |
        v
[WDS Server (Network Unlock Role)]
  |
  +-- Decrypts Payload using Network Unlock Certificate Private Key
  +-- Sends Decryption Key back via DHCP Reply Option
        |
        v
[Client PC]
  |
  +-- Automatically Unlocks OS Volume & Boots Windows
```

If the workstation is stolen or boots outside the local LAN (e.g., on a public network, Wi-Fi, or offline), the DHCP payload request goes unanswered, the Network Unlock fails, and the workstation falls back to prompting the user for a Startup PIN or Recovery Key.

---

## Legacy Impact & Compatibility
* **Wired Network Required**: Network Unlock operates in the pre-boot UEFI phase. Wireless network adapters are not active at this stage; workstations must be connected to the physical corporate switch via an Ethernet cable.
* **UEFI and TPM Requirements**: Client computers must support UEFI DHCP drivers, native UEFI boot (Legacy CSM disabled), and have an active TPM 1.2 or 2.0 chip.
* **PKI Infrastructure**: Deploying Network Unlock requires a functioning Active Directory Certificate Services (AD CS) instance to issue and manage the Network Unlock certificate.

---

## Implementation Steps

### Option A: Group Policy and Server Configuration (Preferred)

#### Step 1: Configure the WDS Server for Network Unlock
1. Install the **Windows Deployment Services (WDS)** role on an internal Windows Server.
2. In Server Manager, select **Add Roles and Features** and check **BitLocker Network Unlock** under Features.
3. Open the Local PKI CA console (`certsrv.msc`) and issue a certificate using the **BitLocker Network Unlock** template.
4. Export the certificate public key (`.cer` file) and export the private key (`.pfx` file).
5. Import the `.pfx` private key certificate into the local WDS server's **Local Computer\Personal** certificate store.
6. Restart the WDS service (`wdssvc`).

#### Step 2: Distribute the Network Unlock Certificate via GPO
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit your GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies`
4. Right-click **BitLocker Network Unlock** and select **Add Network Unlock Certificate**.
5. Import the public `.cer` file exported in Step 1.

#### Step 3: Enforce GPO BitLocker Settings
Navigate to `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption` and configure:

##### 1. General Settings
* **Policy**: `Allow Network Unlock at startup` -> **Enabled**
* **Policy**: `Configure minimum PIN length for startup` -> **Enabled** (Minimum characters: **6**)
* **Policy**: `Choose drive encryption method and cipher strength (Windows 10 [Version 1511] and later)` -> **Enabled** (OS, Fixed, and Removable: **XTS-AES 256-bit**)

##### 2. Operating System Drives
Navigate to `Operating System Drives` subfolder:
* **Policy**: `Require additional authentication at startup` -> **Enabled**
  * `Allow BitLocker without a compatible TPM` -> **Disabled** (unchecked)
  * `Configure TPM startup` -> **Require TPM**
  * `Configure TPM startup PIN` -> **Allow startup PIN with TPM** (Allows Network Unlock auto-unlock)
  * `Configure TPM startup key` -> **Allow startup key with TPM**
  * `Configure TPM startup key and PIN` -> **Allow startup key and PIN with TPM**
* **Policy**: `Allow enhanced PINs for startup` -> **Enabled**
* **Policy**: `Allow Secure Boot for integrity validation` -> **Enabled**
* **Policy**: `Choose how BitLocker-protected operating system drives can be recovered` -> **Enabled**
  * `Allow data recovery agent` -> **Disabled** (unchecked)
  * `Configure user storage of BitLocker recovery information` -> **Require 48-digit recovery password**
  * `Configure user storage of BitLocker recovery key` -> **Do not allow 256-bit recovery key**
  * `Omit recovery options from the BitLocker setup wizard` -> **Enabled** (checked)
  * `Save BitLocker recovery information to AD DS for operating system drives` -> **Enabled** (checked)
  * `Configure storage of BitLocker recovery information to AD DS` -> **Store recovery passwords and key packages**
  * `Do not enable BitLocker until recovery information is stored to AD DS for operating system drives` -> **Enabled** (checked)
* **Policy**: `Configure use of hardware-based encryption for operating system drives` -> **Disabled**
* **Policy**: `Configure use of passwords for operating system drives` -> **Disabled**

##### 3. Fixed Data Drives
Navigate to `Fixed Data Drives` subfolder:
* **Policy**: `Allow access to BitLocker-protected fixed data drives from earlier versions of Windows` -> **Disabled**
* **Policy**: `Choose how BitLocker-protected fixed drives can be recovered` -> **Enabled**
  * `Allow data recovery agent` -> **Enabled** (checked)
  * `Configure user storage of BitLocker recovery information` -> **Allow 48-digit recovery password**
  * `Configure user storage of BitLocker recovery key` -> **Allow 256-bit recovery key**
  * `Omit recovery options from the BitLocker setup wizard` -> **Enabled** (checked)
  * `Save BitLocker recovery information to AD DS for fixed data drives` -> **Enabled** (checked - overridden per user decision)
  * `Configure storage of BitLocker recovery information to AD DS` -> **Backup recovery passwords and key packages**
  * `Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives` -> **Enabled** (checked - overridden to enforce AD backup)
* **Policy**: `Configure use of hardware-based encryption for fixed data drives` -> **Disabled**
* **Policy**: `Configure use of passwords for fixed data drives` -> **Disabled**
* **Policy**: `Configure use of smart cards on fixed data drives` -> **Enabled**
  * `Require use of smart cards on fixed data drives` -> **Enabled** (checked)

##### 4. Removable Data Drives
Navigate to `Removable Data Drives` subfolder:
* **Policy**: `Allow access to BitLocker-protected removable data drives from earlier versions of Windows` -> **Disabled**
* **Policy**: `Choose how BitLocker-protected removable drives can be recovered` -> **Enabled**
  * `Allow data recovery agent` -> **Enabled** (checked)
  * `Configure user storage of BitLocker recovery information` -> **Do not allow 48-digit recovery password**
  * `Configure user storage of BitLocker recovery key` -> **Do not allow 256-bit recovery key**
  * `Omit recovery options from the BitLocker setup wizard` -> **Enabled** (checked)
  * `Save BitLocker recovery information to AD DS for removable data drives` -> **Disabled** (unchecked)
  * `Configure storage of BitLocker recovery information to AD DS` -> **Backup recovery passwords and key packages**
  * `Do not enable BitLocker until recovery information is stored to AD DS for removable data drives` -> **Disabled** (unchecked)
* **Policy**: `Configure use of hardware-based encryption for removable data drives` -> **Disabled**
* **Policy**: `Configure use of passwords for removable data drives` -> **Disabled**
* **Policy**: `Configure use of smart cards on removable data drives` -> **Enabled**
  * `Require use of smart cards on removable data drives` -> **Enabled** (checked)
* **Policy**: `Deny write access to removable drives not protected by BitLocker` -> **Enabled**
  * `Do not allow write access to devices configured in another organization` -> **Disabled** (unchecked)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure BitLocker parameters.

[Download Script: Set-BitLockerEncryption.ps1](implementation_scripts/Set-BitLockerEncryption.ps1)

```powershell
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
```

*To audit local BitLocker and Network Unlock registry settings:*
[Download Script: Test-BitLockerStatus.ps1](audit_scripts/Test-BitLockerStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1 (BitLocker Drive Encryption settings)
* **ANSSI AD Hardening Guide**: Recommendations regarding endpoint encryption and physical key storage security.
* **DoD Windows 11 STIG**: BitLocker startup option requirements and fixed/removable drive recovery rules.
