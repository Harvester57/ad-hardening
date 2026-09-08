# [REQ-DC-158] Harden DMA and Physical Security for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (both physical bare-metal enterprise servers and hypervisor-hosted virtual machines). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-011](../07-paws/harden-dma-and-physical-security.md); for Tier 2 Client Workstations and Member Servers, refer to [REQ-END-017](../08-endpoints/harden-dma-and-physical-security.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

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
      * `2` = `{6bdd1fc1-810f-11d0-bec7-08002be2092f}` (REG_SZ, IEEE 1394 host controller setup class)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs
      * `1` = `PCI\CC_0C0A` (REG_SZ, Blocks Thunderbolt 1, 2, and 3 controllers)
      * `2` = `PCI\CC_0C0010` (REG_SZ, Blocks IEEE 1394 OHCI compliant Firewire controllers)
      * `3` = `PCI\CC_0607` (REG_SZ, Blocks PCI CardBus bridges)
      * `4` = `PCI\CC_0605` (REG_SZ, Blocks PCI-to-PCMCIA bridges)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection
      * `DeviceEnumerationPolicy` = `0` (REG_DWORD, Block all)

---

## Rationale
Domain Controllers represent Tier 0 identity stores hosting the directory database (`NTDS.dit`), Kerberos Ticket Granting Service keys (`krbtgt`), and password hashes for all enterprise principals. While enterprise servers reside in datacenters or branch office wiring closets, physical access threats remain a critical attack vector:

1. **Direct Memory Access (DMA) Threat Vectors**: Hot-plug expansion ports and external peripheral interfaces (such as PCIe hot-plug slots, Thunderbolt, USB4, or external storage expansion cards) permit connected hardware to bypass operating system access controls and perform direct read/write operations against physical DRAM. Attackers utilizing physical DMA consoles (e.g., PCILeech or malicious PCIe expansion cards inserted into physical server chassis) can dump LSASS memory and extract volatile Kerberos keys:
   * **Device Setup Class Lockdown**: Disabling the SBP-2 protocol class (`{d48179be-ec20-11d1-b6b8-00c04fa372a7}`) and IEEE 1394 host controller class (`{6bdd1fc1-810f-11d0-bec7-08002be2092f}`) prevents Windows Server from mounting legacy FireWire storage devices.
   * **Hardware ID Blocking**: Explicitly blocking hardware IDs `PCI\CC_0C0A` (Thunderbolt), `PCI\CC_0C0010` (FireWire), `PCI\CC_0607` (CardBus), and `PCI\CC_0605` (PCMCIA) prevents the installation of unapproved expansion controllers at the hardware bus layer.
   * **BitLocker DMA Under Lock**: Enforcing `DisableExternalDMAUnderLock` blocks DMA device enumeration when the server console is locked, mitigating drive-by hardware attacks on unattended consoles.
   * **Kernel DMA Protection Enforcement**: Enforcing `DeviceEnumerationPolicy = 0` (Block all) guarantees that any peripheral device whose drivers do not explicitly support IOMMU DMA remapping is strictly blocked from executing DMA memory transfers.
2. **Cold Boot & Standby Attacks**: In standard standby sleep states (S1-S3), system RAM remains powered and unencrypted. If an attacker gains physical access to a server in a standby state, they can execute cold-boot extraction or memory analysis to harvest sensitive directory keys. Domain Controllers must operate continuously in full runtime execution states. Disabling standby sleep states forces servers to remain fully operational or enter clean shutdown, ensuring BitLocker encryption keys are sealed by the TPM 2.0 module. Enforcing wake password verification guarantees that any power-state transition requires re-authentication.
3. **Physical USB Exfiltration of Directory Databases**: Rogue insiders or unauthorized datacenter personnel with physical console access can insert USB flash drives to exfiltrate `ntds.dit`, Active Directory backups, or system state data. Enforcing `RDVDenyWriteAccess = 1` prevents writing to removable drives unless protected by BitLocker, while `RDVDenyCrossOrg = 0` eliminates unauthorized cross-organization exceptions.

---

## Legacy Impact & Compatibility
* **Continuous Server Operation**: Domain Controllers are designed for continuous 24/7 service. Disabling standby states (S1-S3) prevents power management misconfigurations or UPS battery events from placing the DC into an unmonitored sleep state, maintaining directory availability.
* **Peripheral Compatibility**: External expansion chassis or non-certified peripherals requiring direct DMA without IOMMU remapping support will be blocked. Enterprise rack-mounted hardware utilizing certified internal PCIe backplanes is fully compatible.
* **Storage Operations**: Local write access to unencrypted USB flash drives is blocked at the console. Backup operations must proceed via automated enterprise backup solutions, dedicated network shares, or BitLocker To Go encrypted drives.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Domain Controllers GPO (e.g., `Default Domain Controllers Policy` or `GPO_Hardening_DC`).
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

#### 3. Device Installation Restrictions (Block SBP-2, 1394, Thunderbolt, and PCI Bridges)
Navigate to:
`Computer Configuration\Administrative Templates\System\Device Installation\Device Installation Restrictions`
* **Policy**: `Prevent installation of devices using drivers that match these device setup classes` -> **Enabled**
  * Click **Show...** and enter:
    * `{d48179be-ec20-11d1-b6b8-00c04fa372a7}`
    * `{6bdd1fc1-810f-11d0-bec7-08002be2092f}`
  * Check **Also apply to matching devices that are already installed** -> **Enabled** (value 1 / True)
* **Policy**: `Prevent installation of devices that match any of these device IDs` -> **Enabled**
  * Click **Show...** and enter:
    * `PCI\CC_0C0A`
    * `PCI\CC_0C0010`
    * `PCI\CC_0607`
    * `PCI\CC_0605`
  * Check **Also apply to matching devices that are already installed** -> **Enabled** (value 1 / True)

#### 4. Kernel DMA Protection (Block All)
Navigate to:
`Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
* **Policy**: `Enable Kernel DMA Protection` -> **Enabled**
  * **Enumeration policy**: Set to **Block all** (value 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on the Domain Controller to apply DMA, Sleep, Device Restriction, and BitLocker USB registry parameters.

[Download Script: Configure-DcDMAPhysicalSecurity.ps1](implementation_scripts/Configure-DcDMAPhysicalSecurity.ps1)

```powershell
# Configure-DcDMAPhysicalSecurity.ps1
# Description: Hardens local registry keys on Domain Controllers to mitigate DMA attacks, disable standby sleep states, enforce wake password, restrict device classes/IDs, and block unencrypted USB writing.

Write-Host "Applying Domain Controller DMA and physical security hardening..." -ForegroundColor Cyan

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

# 4. Device Installation Restrictions (Classes and Hardware IDs)
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
Set-ItemProperty -Path $DenyClassPath -Name "2" -Value "{6bdd1fc1-810f-11d0-bec7-08002be2092f}" -Type String

$DenyIdPath = Join-Path $RestrictPath "DenyDeviceIDs"
if (-not (Test-Path $DenyIdPath)) {
    New-Item -Path $DenyIdPath -Force | Out-Null
}
Set-ItemProperty -Path $DenyIdPath -Name "1" -Value "PCI\CC_0C0A" -Type String
Set-ItemProperty -Path $DenyIdPath -Name "2" -Value "PCI\CC_0C0010" -Type String
Set-ItemProperty -Path $DenyIdPath -Name "3" -Value "PCI\CC_0607" -Type String
Set-ItemProperty -Path $DenyIdPath -Name "4" -Value "PCI\CC_0605" -Type String
Write-Host "[+] Device installation blocks for SBP-2, 1394 host controllers, Thunderbolt, and PCI bridges enabled." -ForegroundColor Green

# 5. Kernel DMA Protection (Block all external DMA)
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $KDmaPath)) {
    New-Item -Path $KDmaPath -Force | Out-Null
}
Set-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "[+] Kernel DMA Protection DeviceEnumerationPolicy set to 0 (Block all)." -ForegroundColor Green

Write-Host "Domain Controller DMA and physical security settings applied successfully." -ForegroundColor Green
```

*To audit local Domain Controller DMA and physical security configuration:*
[Download Script: Test-DcDMAPhysicalSecurity.ps1](audit_scripts/Test-DcDMAPhysicalSecurity.ps1)

```powershell
# Test-DcDMAPhysicalSecurity.ps1
# Description: Audits local registry configuration for standby settings, wake password, DMA protection under lock, USB restrictions, and blocked device classes/IDs on Domain Controllers.

Write-Host "--- Auditing Domain Controller DMA and Physical Security ---" -ForegroundColor Cyan
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

$DenyId = Get-ItemProperty -Path $RestrictPath -Name "DenyDeviceIDs" -ErrorAction SilentlyContinue
$DenyIdVal = if ($DenyId) { $DenyId.DenyDeviceIDs } else { 0 }
$DenyIdColor = if ($DenyIdVal -eq 1) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Prevent Device Setup Class Installation: $($DenyDevVal) (Required = 1)" -ForegroundColor $DenyDevColor
Write-Host "    - Prevent Device ID Installation: $($DenyIdVal) (Required = 1)" -ForegroundColor $DenyIdColor

$DenyClassPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
$Sbp2 = Get-ItemProperty -Path $DenyClassPath -Name "1" -ErrorAction SilentlyContinue
$Sbp2Val = if ($Sbp2) { $Sbp2."1" } else { "" }
$Sbp2Color = if ($Sbp2Val -eq "{d48179be-ec20-11d1-b6b8-00c04fa372a7}") { "Green" } else { $isCompliant = $false; "Red" }

$Host1394 = Get-ItemProperty -Path $DenyClassPath -Name "2" -ErrorAction SilentlyContinue
$Host1394Val = if ($Host1394) { $Host1394."2" } else { "" }
$Host1394Color = if ($Host1394Val -eq "{6bdd1fc1-810f-11d0-bec7-08002be2092f}") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked SBP-2 Setup Class: '$($Sbp2Val)' (Required = '{d48179be-ec20-11d1-b6b8-00c04fa372a7}')" -ForegroundColor $Sbp2Color
Write-Host "    - Blocked 1394 Host Setup Class: '$($Host1394Val)' (Required = '{6bdd1fc1-810f-11d0-bec7-08002be2092f}')" -ForegroundColor $Host1394Color

$DenyIdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
$DId1 = Get-ItemProperty -Path $DenyIdPath -Name "1" -ErrorAction SilentlyContinue
$DId1Val = if ($DId1) { $DId1."1" } else { "" }
$DId1Color = if ($DId1Val -eq "PCI\CC_0C0A") { "Green" } else { $isCompliant = $false; "Red" }

$DId2 = Get-ItemProperty -Path $DenyIdPath -Name "2" -ErrorAction SilentlyContinue
$DId2Val = if ($DId2) { $DId2."2" } else { "" }
$DId2Color = if ($DId2Val -eq "PCI\CC_0C0010") { "Green" } else { $isCompliant = $false; "Red" }

$DId3 = Get-ItemProperty -Path $DenyIdPath -Name "3" -ErrorAction SilentlyContinue
$DId3Val = if ($DId3) { $DId3."3" } else { "" }
$DId3Color = if ($DId3Val -eq "PCI\CC_0607") { "Green" } else { $isCompliant = $false; "Red" }

$DId4 = Get-ItemProperty -Path $DenyIdPath -Name "4" -ErrorAction SilentlyContinue
$DId4Val = if ($DId4) { $DId4."4" } else { "" }
$DId4Color = if ($DId4Val -eq "PCI\CC_0605") { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Blocked Device ID PCI\CC_0C0A: '$($DId1Val)' (Required = 'PCI\CC_0C0A')" -ForegroundColor $DId1Color
Write-Host "    - Blocked Device ID PCI\CC_0C0010: '$($DId2Val)' (Required = 'PCI\CC_0C0010')" -ForegroundColor $DId2Color
Write-Host "    - Blocked Device ID PCI\CC_0607: '$($DId3Val)' (Required = 'PCI\CC_0607')" -ForegroundColor $DId3Color
Write-Host "    - Blocked Device ID PCI\CC_0605: '$($DId4Val)' (Required = 'PCI\CC_0605')" -ForegroundColor $DId4Color

# 5. Audit Kernel DMA Protection Setting
$KDmaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPol = Get-ItemProperty -Path $KDmaPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue
$EnumPolVal = if ($EnumPol) { $EnumPol.DeviceEnumerationPolicy } else { 2 }
$EnumPolColor = if ($EnumPolVal -eq 0) { "Green" } else { $isCompliant = $false; "Red" }

Write-Host "    - Kernel DMA Protection Policy: $($EnumPolVal) (Required = 0 [Block all])" -ForegroundColor $EnumPolColor

# 6. Final Compliance Assessment
if ($isCompliant) {
    Write-Host "[+] Audit Result: SECURE - Domain Controller DMA and physical security controls are fully compliant." -ForegroundColor Green
} else {
    Write-Host "[-] Audit Result: VULNERABLE - One or more Domain Controller DMA or physical security settings do not meet baseline requirements." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.2.1 (BitLocker Drive Encryption), Section 18.8.19.1 (Kernel DMA Protection), Section 18.8.21.3 (Device Installation Restrictions)
* **ANSSI AD Hardening Guide**: Recommendations R4 & R58 (Domain Controller host security, storage encryption, and physical peripheral restrictions)
* **NIST SP 800-207**: Zero Trust Architecture - Physical Host Boundary Integrity
