# Hardening Requirement: Enable BitLocker and Network Unlock

## Target Scope
* **Applicable Systems**: Tier 2 client workstations.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives`
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies\BitLocker Network Unlock`
  * **Registry Location**: `HKLM\SOFTWARE\Policies\Microsoft\FVE`
    * `AllowNetworkUnlock` = `1` (REG_DWORD)
    * `MinimumPIN` = `6` (REG_DWORD)
    * `EnableBDEWithNoTPM` = `1` (REG_DWORD)
    * `UseTPM` = `2` (REG_DWORD, Allowed / Required depending on baseline)
    * `UseTPMPIN` = `2` (REG_DWORD, Allowed)
    * `UseTPMKey` = `2` (REG_DWORD, Allowed)
    * `UseTPMKeyPIN` = `2` (REG_DWORD, Allowed)

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
1. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives`
2. Configure the following settings:
   * **Policy**: `Require additional authentication at startup`
     * **Setting**: `Enabled`
     * **Configure Options**:
       * Set `Configure TPM startup`: `Require TPM` (or `Allow TPM`).
       * Set `Configure TPM startup PIN`: `Allow startup PIN with TPM` (or `Require startup PIN with TPM` based on risk assessment).
       * Set `Configure TPM startup key`: `Allow startup key with TPM`.
       * Set `Configure TPM startup key and PIN`: `Allow startup key and PIN with TPM`.
       * Check `Allow BitLocker without a compatible TPM` to `Disabled` (or `Enabled` if required by hardware compatibility).
   * **Policy**: `Allow Network Unlock at startup`
     * **Setting**: `Enabled`
   * **Policy**: `Configure minimum PIN length for startup`
     * **Setting**: `Enabled`
     * **Minimum characters**: `6`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure BitLocker parameters.

[Download Script: Set-BitLockerEncryption.ps1](implementation_scripts/Set-BitLockerEncryption.ps1)

```powershell
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
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.1.1 (Require additional authentication at startup), Section 18.2.1.5 (Allow Network Unlock at startup)
* **ANSSI AD Hardening Guide**: Recommendations regarding endpoint encryption and physical key storage security.
* **DoD Windows 11 STIG**: BitLocker startup option requirements.

---

## Rationale
BitLocker Drive Encryption protects the operating system volume from offline attacks, data tampering, and data theft when the device is powered off or stolen. Without full disk encryption, an attacker with physical access to a workstation can extract the hard drive, mount it on a non-secure system, bypass operating system security controls, dump local password databases (SAM), and access cached domain credentials.

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
1. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives`
2. Configure the following settings:
   * **Policy**: `Require additional authentication at startup`
   * **Setting**: `Enabled`
   * **Configure Options**:
     * Set `Configure TPM startup`: `Require TPM`.
     * Check `Allow BitLocker without a compatible TPM` to `Disabled`.
   * **Policy**: `Allow Network Unlock at startup`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure BitLocker parameters.

[Download Script: Set-BitLockerEncryption.ps1](implementation_scripts/Set-BitLockerEncryption.ps1)

```powershell
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
```

*To audit local BitLocker and Network Unlock registry settings:*
[Download Script: Test-BitLockerStatus.ps1](audit_scripts/Test-BitLockerStatus.ps1)

```powershell
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
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.2.1.1 (Require additional authentication at startup), Section 18.2.1.5 (Allow Network Unlock at startup)
* **ANSSI AD Hardening Guide**: Recommendations regarding endpoint encryption and physical key storage security.
