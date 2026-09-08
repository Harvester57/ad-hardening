# [REQ-END-017] Harden DMA and Physical Security

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients (Workstations / Laptops). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-011](../07-paws/harden-dma-and-physical-security.md); for Domain Controllers, refer to [REQ-DC-158](../02-domain-controllers/harden-dma-and-physical-security.md)).*
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * Computer Configuration\Administrative Templates\System\Power Management\Sleep Settings
    * Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions
    * Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption
    * Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Removable Data Drives
    * Computer Configuration\Administrative Templates\System\Kernel DMA Protection
  * **Registry Locations**:
    * HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab
      * `ACSettingIndex` = `0` (REG_DWORD, Disables standby plugged in)
      * `DCSettingIndex` = `0` (REG_DWORD, Disables standby on battery)
    * HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51
      * `ACSettingIndex` = `1` (REG_DWORD, Require password when computer wakes plugged in)
      * `DCSettingIndex` = `1` (REG_DWORD, Require password when computer wakes on battery)
    * HKLM\SOFTWARE\Policies\Microsoft\FVE
      * `DisableExternalDMAUnderLock` = `1` (REG_DWORD)
      * `RDVDenyCrossOrg` = `0` (REG_DWORD)
    * HKLM\System\CurrentControlSet\Policies\Microsoft\FVE
      * `RDVDenyWriteAccess` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
      * `DenyDeviceClasses` = `1` (REG_DWORD)
      * `DenyDeviceClassesRetroactive` = `1` (REG_DWORD)
      * `DenyDeviceIDs` = `1` (REG_DWORD)
      * `DenyDeviceIDsRetroactive` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses
      * `1` = `{d48179be-ec20-11d1-b6b8-00c04fa372a7}` (REG_SZ, SBP-2 device setup class)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs
      * `1` = `PCI\CC_0C0A` (REG_SZ, Blocks Thunderbolt 1, 2, and 3 controllers)
      * `2` = `PCI\CC_0C0010` (REG_SZ, Blocks IEEE 1394 OHCI compliant Firewire controllers)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection
      * `DeviceEnumerationPolicy` = `0` (REG_DWORD, Block all)

---

## Rationale
Physical access to an endpoint introduces distinct attack vectors that bypass traditional OS privilege separation:

1. **Direct Memory Access (DMA) Attacks**: Hot-plug buses (such as FireWire, Thunderbolt, and USB4) permit connected peripherals to read and write directly to system memory without operating system mediation. Attackers connect specialized hardware (e.g., PCILeech) to exposed external ports to extract BitLocker encryption keys, NTLM hashes, or active session tokens directly from RAM:
   * Disabling the Serial Bus Protocol 2 (SBP-2) setup class (`{d48179be-ec20-11d1-b6b8-00c04fa372a7}`) blocks FireWire/IEEE 1394 DMA controllers.
   * Blocking hardware device IDs `PCI\CC_0C0A` (Thunderbolt) and `PCI\CC_0C0010` (1394 OHCI FireWire) halts driver initialization for dangerous hot-plug controllers. *(Note: On Tier 0 PAWs, additional legacy controller setup classes and CardBus/PCMCIA bridges are blocked under [REQ-PAW-011](../07-paws/harden-dma-and-physical-security.md)).*
   * Enforcing `DisableExternalDMAUnderLock` prevents DMA requests while the workstation screen is locked.
   * `DeviceEnumerationPolicy` set to **Block all** (0) ensures devices lacking DMA-remapping isolation support cannot execute unauthorized memory access transfers.
2. **Cold Boot Attacks & Sleep Vulnerabilities**: When an endpoint enters standby sleep states (S1-S3), system RAM remains powered and active. If an unattended laptop or desktop is stolen while in standby, an attacker can quickly reboot the machine or chill the DRAM chips to dump memory contents and retrieve BitLocker keys. Disabling standby forces systems to transition to Hibernation (S4)/Shutdown, where RAM contents are flushed to the BitLocker-encrypted disk and sealed by the TPM. Enforcing a password upon wake prevents unauthorized physical resumption.
3. **USB Data Exfiltration**: Blocking write access to removable drives unless they are encrypted with BitLocker (`RDVDenyWriteAccess`) prevents users or malicious agents from copying confidential organizational data to unauthorized, unencrypted USB media. Setting `RDVDenyCrossOrg = 0` enforces organization-wide BitLocker compliance.

---

## Legacy Impact & Compatibility
* **Standby Disabled**: Workstations and laptops will bypass standby states and enter hibernation when closed or idle. This preserves battery life but may increase the time required to resume user sessions by a few seconds.
* **DMA Device Support**: External peripherals requiring DMA without supporting memory remapping (such as legacy docking stations or external display adapters) will be blocked. Organizations should deploy modern docks compatible with Kernel DMA Protection.
* **USB Writing**: Standard USB flash drives will be read-only unless encrypted via BitLocker on the endpoint. Users must be provisioned with BitLocker To Go encrypted media.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting endpoints (e.g., `GPO_Hardening_DMA_Physical`).
3. Configure the following settings:

#### 1. Power Management (Disable Standby & Require Wake Password)
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

#### 3. Device Installation Restrictions (Block SBP-2 Setup Class & PCI Device IDs)
Navigate to:
`Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions`
* **Policy**: `Prevent installation of devices using drivers that match these device setup classes` -> **Enabled**
  * Click **Show...** and enter: `{d48179be-ec20-11d1-b6b8-00c04fa372a7}`
  * Check **Also apply to matching devices that are already installed** -> **Enabled** (value 1 / True)
* **Policy**: `Prevent installation of devices that match any of these device IDs` -> **Enabled**
  * Click **Show...** and enter:
    * `PCI\CC_0C0A`
    * `PCI\CC_0C0010`
  * Check **Also apply to matching devices that are already installed** -> **Enabled** (value 1 / True)

#### 4. Kernel DMA Protection (Block All)
Navigate to:
`Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
* **Policy**: `Enable Kernel DMA Protection` -> **Enabled**
  * **Enumeration policy**: Set to **Block all** (value 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to apply DMA, Sleep, Device Restriction, and BitLocker USB registry parameters.

[Download Script: Set-DMAPhysicalSecurity.ps1](implementation_scripts/Set-DMAPhysicalSecurity.ps1)

```powershell
# Set-DMAPhysicalSecurity.ps1
# Description: Hardens local registry keys to mitigate DMA attacks, disable standby sleep states, enforce wake password, and restrict unencrypted USB writing.

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

# 4. Device Installation Restrictions (Block SBP-2 class and PCI device IDs)
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
if (-not (Test-Path $RestrictPath)) {
    New-Item -Path $RestrictPath -Force | Out-Null
}
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -Value 1 -Type DWord
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceClassesRetroactive" -Value 1 -Type DWord
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDs" -Value 1 -Type DWord
Set-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDsRetroactive" -Value 1 -Type DWord

$DenyClassPath = Join-Path $RestrictPath "DenyDeviceClasses"
if (-not (Test-Path $DenyClassPath)) {
    New-Item -Path $DenyClassPath -Force | Out-Null
}
Set-ItemProperty -Path $DenyClassPath -Name "1" -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" -Type String

$DenyIDPath = Join-Path $RestrictPath "DenyDeviceIDs"
if (-not (Test-Path $DenyIDPath)) {
    New-Item -Path $DenyIDPath -Force | Out-Null
}
Set-ItemProperty -Path $DenyIDPath -Name "1" -Value "PCI\CC_0C0A" -Type String
Set-ItemProperty -Path $DenyIDPath -Name "2" -Value "PCI\CC_0C0010" -Type String
Write-Host "[+] Device installation blocks for SBP-2 class, PCI\CC_0C0A, and PCI\CC_0C0010 enabled." -ForegroundColor Green

# 5. Kernel DMA Protection (Block all external DMA)
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $KDmaPath)) {
    New-Item -Path $KDmaPath -Force | Out-Null
}
Set-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "[+] Kernel DMA Protection DeviceEnumerationPolicy set to 0 (Block all)." -ForegroundColor Green

Write-Host "DMA and physical security settings applied successfully." -ForegroundColor Green
```

*To audit local DMA and physical security configuration:*
[Download Script: Test-DMAPhysicalSecurity.ps1](audit_scripts/Test-DMAPhysicalSecurity.ps1)

```powershell
# Test-DMAPhysicalSecurity.ps1
# Description: Audits local registry configuration for standby settings, wake password, DMA protection under lock, USB restrictions, and blocked device setup classes/IDs.

Write-Host "--- Auditing DMA and Physical Security ---" -ForegroundColor Cyan
$isCompliant = $true

# 1. Audit Standby Settings
$SleepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab"
$AcSleep = Get-ItemProperty -Path $SleepPath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcSleep = Get-ItemProperty -Path $SleepPath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcSleepVal = if ($AcSleep) { $AcSleep.ACSettingIndex } else { 1 }
$DcSleepVal = if ($DcSleep) { $DcSleep.DCSettingIndex } else { 1 }

$AcSleepColor = if ($AcSleepVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }
$DcSleepColor = if ($DcSleepVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Standby Sleep State (Plugged In) Setting: $($AcSleepVal) (Required = 0 [Disabled])" -ForegroundColor $AcSleepColor
Write-Host "    - Standby Sleep State (On Battery) Setting: $($DcSleepVal) (Required = 0 [Disabled])" -ForegroundColor $DcSleepColor

# 2. Audit Wake Password Requirement
$WakePath = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
$AcWake = Get-ItemProperty -Path $WakePath -Name "ACSettingIndex" -ErrorAction SilentlyContinue
$DcWake = Get-ItemProperty -Path $WakePath -Name "DCSettingIndex" -ErrorAction SilentlyContinue

$AcWakeVal = if ($AcWake) { $AcWake.ACSettingIndex } else { 0 }
$DcWakeVal = if ($DcWake) { $DcWake.DCSettingIndex } else { 0 }

$AcWakeColor = if ($AcWakeVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }
$DcWakeColor = if ($DcWakeVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Wake Password Required (Plugged In): $($AcWakeVal) (Required = 1 [Enabled])" -ForegroundColor $AcWakeColor
Write-Host "    - Wake Password Required (On Battery): $($DcWakeVal) (Required = 1 [Enabled])" -ForegroundColor $DcWakeColor

# 3. Audit BitLocker Settings
$FvePath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
$DmaLock = Get-ItemProperty -Path $FvePath -Name "DisableExternalDMAUnderLock" -ErrorAction SilentlyContinue
$DmaLockVal = if ($DmaLock) { $DmaLock.DisableExternalDMAUnderLock } else { 0 }
$DmaLockColor = if ($DmaLockVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

$CrossOrg = Get-ItemProperty -Path $FvePath -Name "RDVDenyCrossOrg" -ErrorAction SilentlyContinue
$CrossOrgVal = if ($CrossOrg) { $CrossOrg.RDVDenyCrossOrg } else { 1 }
$CrossOrgColor = if ($CrossOrgVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

$FvePolicyPath = "HKLM:\System\CurrentControlSet\Policies\Microsoft\FVE"
$UsbWrite = Get-ItemProperty -Path $FvePolicyPath -Name "RDVDenyWriteAccess" -ErrorAction SilentlyContinue
$UsbWriteVal = if ($UsbWrite) { $UsbWrite.RDVDenyWriteAccess } else { 0 }
$UsbWriteColor = if ($UsbWriteVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Disable DMA Under Lock: $($DmaLockVal) (Required = 1)" -ForegroundColor $DmaLockColor
Write-Host "    - USB Deny Cross Org Removable Drives: $($CrossOrgVal) (Required = 0)" -ForegroundColor $CrossOrgColor
Write-Host "    - USB Unencrypted Write Block: $($UsbWriteVal) (Required = 1)" -ForegroundColor $UsbWriteColor

# 4. Audit Device Restriction Settings
$RestrictPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
$DenyDev = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceClasses" -ErrorAction SilentlyContinue
$DenyDevVal = if ($DenyDev) { $DenyDev.DenyDeviceClasses } else { 0 }
$DenyDevColor = if ($DenyDevVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

$DenyID = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
$DenyIDVal = if ($DenyID) { $DenyID.DenyDeviceIDs } else { 0 }
$DenyIDColor = if ($DenyIDVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Prevent Device Setup Class Installation: $($DenyDevVal) (Required = 1)" -ForegroundColor $DenyDevColor
Write-Host "    - Prevent Device ID Installation: $($DenyIDVal) (Required = 1)" -ForegroundColor $DenyIDColor

$DenyClassPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$Sbp2 = Get-ItemProperty -Path $DenyClassPath -Name "1" -ErrorAction SilentlyContinue
$Sbp2Val = if ($Sbp2) { $Sbp2."1" } else { "" }
$Sbp2Color = if ($Sbp2Val -eq "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked SBP-2 Setup Class: '$($Sbp2Val)' (Required = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')" -ForegroundColor $Sbp2Color

$DenyIDPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
$DId1 = Get-ItemProperty -Path $DenyIDPath -Name "1" -ErrorAction SilentlyContinue
$DId1Val = if ($DId1) { $DId1."1" } else { "" }
$DId1Color = if ($DId1Val -eq "PCI\CC_0C0A") { "Green" } else { $isCompliant = $false; "Red" }

$DId2 = Get-ItemProperty -Path $DenyIDPath -Name "2" -ErrorAction SilentlyContinue
$DId2Val = if ($DId2) { $DId2."2" } else { "" }
$DId2Color = if ($DId2Val -eq "PCI\CC_0C0010") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked Device ID PCI\CC_0C0A: '$($DId1Val)' (Required = 'PCI\CC_0C0A')" -ForegroundColor $DId1Color
Write-Host "    - Blocked Device ID PCI\CC_0C0010: '$($DId2Val)' (Required = 'PCI\CC_0C0010')" -ForegroundColor $DId2Color

# 5. Audit Kernel DMA Protection Setting
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPol = Get-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
$EnumPolVal = if ($EnumPol) { $EnumPol.DeviceEnumerationPolicy } else { 2 }
$EnumPolColor = if ($EnumPolVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Kernel DMA Protection Policy: $($EnumPolVal) (Required = 0 [Block all])" -ForegroundColor $EnumPolColor

# 6. Final Compliance Assessment
if ($isCompliant) {
    Write-Host "[+] Audit Result: SECURE - Endpoint DMA and physical security controls are fully compliant." -ForegroundColor Green
} else {
    Write-Host "[-] Audit Result: VULNERABLE - One or more endpoint DMA or physical security settings do not meet baseline requirements." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1 (BitLocker settings), Section 18.8.19.1 (Kernel DMA Protection), Section 18.8.21.3 (Device Installation restrictions)
* **ANSSI AD Hardening Guide**: Recommendations on workstation storage encryption and hardware interface security
