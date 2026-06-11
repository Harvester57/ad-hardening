# Hardening Requirement: Harden DMA and Physical Security

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients (Workstations / Laptops)
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * Computer Configuration\Administrative Templates\System\Power Management\Sleep Settings
    * Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions
    * Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption
  * **Registry Locations**:
    * HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab
      * `ACSettingIndex` = `0` (REG_DWORD, Disables standby plugged in)
      * `DCSettingIndex` = `0` (REG_DWORD, Disables standby on battery)
    * HKLM\SOFTWARE\Policies\Microsoft\FVE
      * `DisableExternalDMAUnderLock` = `1` (REG_DWORD)
      * `RDVDenyCrossOrg` = `0` (REG_DWORD)
    * HKLM\System\CurrentControlSet\Policies\Microsoft\FVE
      * `RDVDenyWriteAccess` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
      * `DenyDeviceClasses` = `1` (REG_DWORD)
      * `DenyDeviceClassesRetroactive` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses
      * `1` = `{d48179be-ec20-11d1-b6b8-00c04fa372a7}` (REG_SZ, SBP-2 device setup class)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection
      * `DeviceEnumerationPolicy` = `1` (REG_DWORD, Block until user logon)

---

## Rationale
Physical access to an endpoint introduces distinct attack vectors that bypass traditional OS privilege separation:

1. **Direct Memory Access (DMA) Attacks**: Hot-plug buses (like FireWire, Thunderbolt, and USB4) permit devices to read and write directly to system memory without operating system mediation. Attackers connect specialized hardware (e.g., PCILeech) to hot-plug ports to extract BitLocker encryption keys or session tokens directly from RAM.
   * Disabling the Serial Bus Protocol 2 (SBP-2) setup class (`{d48179be-ec20-11d1-b6b8-00c04fa372a7}`) blocks FireWire/IEEE 1394 DMA controllers.
   * Enforcing `DisableExternalDMAUnderLock` prevents DMA requests when the screen is locked.
   * `DeviceEnumerationPolicy` restricts external DMA execution until user authentication occurs.
2. **Cold Boot Attacks**: When a system enters standby sleep states (S1-S3), the system RAM remains powered. If a laptop is stolen while in standby, an attacker can quickly reboot the machine or cool the RAM chips to dump their contents, extracting credentials or disk encryption keys. Disabling standby forces the system to either remain fully active or enter Hibernation (S4)/Shutdown, where memory contents are encrypted on disk or cleared.
3. **USB Data Exfiltration**: Blocking write access to removable drives unless they are encrypted with BitLocker (`RDVDenyWriteAccess`) prevents users or malicious agents from copying confidential data to unauthorized USB media.

---

## Legacy Impact & Compatibility
* **Standby Disabled**: Workstations and laptops will bypass standby states and enter hibernation when closed or idle. This preserves battery but may increase the time required to resume user sessions by a few seconds.
* **DMA Device Support**: Non-compliant external peripherals (such as legacy docking stations or external display adapters) that require DMA without supporting remapping may not work until the user logs on, or may be blocked entirely.
* **USB Writing**: Standard USB flash drives will be read-only unless encrypted via BitLocker on the endpoint. This requires training users on BitLocker To Go deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting endpoints (e.g., `GPO_Hardening_DMA_Physical`).
3. Configure the following settings:

#### 1. Power Management (Disable Standby)
Navigate to:
`Computer Configuration\Administrative Templates\System\Power Management\Sleep Settings`
* **Policy**: `Allow standby states (S1-S3) when sleeping (plugged in)` -> **Disabled**
* **Policy**: `Allow standby states (S1-S3) when sleeping (on battery)` -> **Disabled**
* **Policy**: `Require a password when a computer wakes (plugged in)` -> **Enabled**
* **Policy**: `Require a password when a computer wakes (on battery)` -> **Enabled**

#### 2. BitLocker Removable Storage & DMA
Navigate to:
`Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption`
* **Policy**: `Disable new DMA devices when this computer is locked` -> **Enabled**

Navigate to:
`Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Removable Data Drives`
* **Policy**: `Deny write access to removable drives not protected by BitLocker` -> **Enabled**
  * Check **Do not allow write access to devices configured in another organization** -> **Disabled** (value 0 / False)

#### 3. Device Installation Restrictions (Block SBP-2 Setup Class)
Navigate to:
`Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions`
* **Policy**: `Prevent installation of devices using drivers that match these device setup classes` -> **Enabled**
  * Click **Show...** and enter: `{d48179be-ec20-11d1-b6b8-00c04fa372a7}`
  * Check **Also apply to matching devices that are already installed** -> **Enabled** (value 1 / True)

#### 4. Kernel DMA Protection
Navigate to:
`Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
* **Policy**: `Enable Kernel DMA Protection` -> **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply DMA, Sleep, and BitLocker USB registry parameters.

```powershell
# Set-DMAPhysicalSecurity.ps1
# Description: Hardens local registry keys to mitigate DMA attacks, disable standby sleep states, and restrict unencrypted USB writing.

Write-Host "Applying DMA and physical security hardening..." -ForegroundColor Cyan

# 1. Disable Standby Sleep States (S1-S3)
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
if (-not (Test-Path $SleepPath)) {
    New-Item -Path $SleepPath -Force | Out-Null
}
Set-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -Value 0 -Type DWord
Set-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -Value 0 -Type DWord
Write-Host "[+] Standby sleep states (S1-S3) disabled." -ForegroundColor Green

# 2. Configure Wake Password Requirement
$WakePath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
if (-not (Test-Path $WakePath)) {
    New-Item -Path $WakePath -Force | Out-Null
}
Set-ItemProperty -Path $WakePath -Name "ACSettingIndex" -Value 1 -Type DWord
Set-ItemProperty -Path $WakePath -Name "DCSettingIndex" -Value 1 -Type DWord
Write-Host "[+] Wake password requirement enforced." -ForegroundColor Green

# 3. BitLocker DMA and Removable Storage Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
if (-not (Test-Path $FvePath)) {
    New-Item -Path $FvePath -Force | Out-Null
}
Set-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -Value 1 -Type DWord
Set-ItemProperty -Path $FvePath -Name "RDVDenyCrossOrg" -Value 0 -Type DWord

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
if (-not (Test-Path $FvePolicyPath)) {
    New-Item -Path $FvePolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -Value 1 -Type DWord
Write-Host "[+] BitLocker DMA under lock and unencrypted USB write blocks configured." -ForegroundColor Green

# 4. Device Installation Restrictions (Block SBP-2 class)
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if (-not (Test-Path $RestrictPath)) {
    New-Item -Path $RestrictPath -Force | Out-Null
}
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -Value 1 -Type DWord
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClassesRetroactive" -Value 1 -Type DWord

$DenyClassPath = Join-Path $RestrictPath "DenyDeviceClasses"
if (-not (Test-Path $DenyClassPath)) {
    New-Item -Path $DenyClassPath -Force | Out-Null
}
Set-ItemProperty -Path $DenyClassPath -Name "1" -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" -Type String
Write-Host "[+] Device installation blocks for SBP-2 class enabled." -ForegroundColor Green

# 5. Kernel DMA Protection (Block until logon for standard clients)
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $KDmaPath)) {
    New-Item -Path $KDmaPath -Force | Out-Null
}
Set-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -Value 1 -Type DWord
Write-Host "[+] Kernel DMA Protection DeviceEnumerationPolicy set to 1 (Block until logon)." -ForegroundColor Green

Write-Host "DMA and physical security settings applied successfully." -ForegroundColor Green
```

*To audit local DMA and physical security configuration:*
```powershell
# Test-DMAPhysicalSecurity.ps1
# Description: Audits local registry configuration for standby settings, DMA protection under lock, USB restrictions, and blocked device setup classes.

Write-Host "--- Auditing DMA and Physical Security ---" -ForegroundColor Cyan

# 1. Audit Standby Settings
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$AcSleep = Get-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcSleep = Get-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcSleepVal = if ($AcSleep) { $AcSleep.ACSettingIndex } else { 1 }
$DcSleepVal = if ($DcSleep) { $DcSleep.DCSettingIndex } else { 1 }

$AcSleepColor = if ($AcSleepVal -eq 0) { "Green" } else { "Red" }
$DcSleepColor = if ($DcSleepVal -eq 0) { "Green" } else { "Red" }

Write-Host "    - Standby Sleep State (Plugged In) Setting: $AcSleepVal (Required = 0 [Disabled])" -ForegroundColor $AcSleepColor
Write-Host "    - Standby Sleep State (On Battery) Setting: $DcSleepVal (Required = 0 [Disabled])" -ForegroundColor $DcSleepColor

# 2. Audit BitLocker Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$DmaLock = Get-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -ErrorAction SilentlyContinue
$DmaLockVal = if ($DmaLock) { $DmaLock.DisableExternalDMAUnderLock } else { 0 }
$DmaLockColor = if ($DmaLockVal -eq 1) { "Green" } else { "Red" }

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
$UsbWrite = Get-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
$UsbWriteVal = if ($UsbWrite) { $UsbWrite.RDVDenyWriteAccess } else { 0 }
$UsbWriteColor = if ($UsbWriteVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Disable DMA Under Lock: $DmaLockVal (Required = 1)" -ForegroundColor $DmaLockColor
Write-Host "    - USB Unencrypted Write Block: $UsbWriteVal (Required = 1)" -ForegroundColor $UsbWriteColor

# 3. Audit Device Restriction Settings
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$DenyDev = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
$DenyDevVal = if ($DenyDev) { $DenyDev.DenyDeviceClasses } else { 0 }
$DenyDevColor = if ($DenyDevVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Prevent Device Setup Class Installation: $DenyDevVal (Required = 1)" -ForegroundColor $DenyDevColor

$DenyClassPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$Sbp2 = Get-ItemProperty -Path $DenyClassPath -Name "1" -ErrorAction SilentlyContinue
$Sbp2Val = if ($Sbp2) { $Sbp2."1" } else { "" }
$Sbp2Color = if ($Sbp2Val -eq "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") { "Green" } else { "Red" }

Write-Host "    - Blocked SBP-2 Setup Class: '$Sbp2Val' (Required = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')" -ForegroundColor $Sbp2Color

# 4. Audit Kernel DMA Protection Setting
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPol = Get-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
$EnumPolVal = if ($EnumPol) { $EnumPol.DeviceEnumerationPolicy } else { 2 }
$EnumPolColor = if ($EnumPolVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Kernel DMA Protection Policy: $EnumPolVal (Required = 1 [Block until logon])" -ForegroundColor $EnumPolColor
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1 (BitLocker settings), Section 18.8.19.1 (Kernel DMA Protection), Section 18.8.21.3 (Device Installation restrictions)
* **ANSSI AD Hardening Guide**: Recommendations on workstation storage encryption and hardware interface security
