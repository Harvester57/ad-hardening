# [REQ-END-013] UEFI Firmware Security Hardening

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Hardware/UEFI Firmware Configuration Menu

---

## Rationale
Standard Tier 2 endpoints (such as employee laptops and workstations) and member servers are frequently exposed to physical theft, loss, and unauthorized local access in branch offices or remote environments. If the firmware on these systems is left unsecured, an attacker can modify boot settings, bypass operating system security controls, or execute physical DMA and offline decryption attacks.

Securing the firmware level ensures:
1. **Firmware Integrity**: Enforcing a UEFI administrator password prevents unauthorized configuration modifications, such as disabling Secure Boot, TPM, or hardware virtualization features.
2. **Native UEFI Boot**: Disabling the Compatibility Support Module (CSM) or Legacy BIOS options forces native UEFI mode, which is mandatory for activating UEFI Secure Boot and Virtualization-Based Security (VBS).
3. **Restricted Boot Paths**: Restricting the boot order to the primary internal storage device prevents users or attackers from booting unauthorized operating systems or diagnostic tools from USB media or untrusted local networks.
4. **BIOS Rollback Prevention**: Enforcing firmware update signature validation and blocking BIOS rollbacks mitigates the risk of downgrade attacks targeting known firmware vulnerabilities.
5. **Virtualization-Based Security Foundation**: Enabling CPU Virtualization Extensions (Intel VT-x / AMD-V) and IOMMU (Intel VT-d / AMD-Vi) at the firmware level establishes the mandatory hardware isolation required by the Windows Hypervisor to run VBS, Credential Guard, and Kernel DMA Protection.
6. **Platform Measurement Integrity**: Disabling Fast Boot forces the firmware to execute full hardware initialization, device checks, and complete TPM self-tests/PCR measurements at every boot, ensuring platform integrity and correct state validation.

---

## Legacy Impact & Compatibility
* **Enterprise Management**: Configuring UEFI passwords manually across thousands of endpoints is administratively impractical. Enterprise deployment tools (such as Dell Command | Configure, HP Client Management Script Library, or Lenovo BIOS WMI interfaces) must be used to automate setting and updating BIOS passwords.
* **Imaging Workflows**: Standard corporate imaging (PXE boot) requires network boot to be temporarily enabled. If PXE is required, it must be restricted to authorized enterprise subnets and secured with PXE access passwords in the deployment console (e.g., MECM/SCCM).
* **Legacy Partitions**: Legacy BIOS endpoints running on MBR partition layouts must be converted to GPT using MBR2GPT.exe prior to enabling native UEFI boot mode.

---

## Implementation Steps

### Option A: UEFI Firmware Configuration (Preferred)

UEFI parameters can be configured manually on individual systems or programmatically automated using enterprise vendor tools.

#### 1. Manual UEFI Configuration (Small Environments or Standalone Servers)
1. Restart the system and press the vendor-specific key during startup POST (typically Delete, F2, F10, or F12) to enter the UEFI utility.
2. Locate the **Security** tab:
   * Define a strong **Administrator Password** (also called **Supervisor Password**). Do not set a User Password, as that prompts for password entry on every standard boot.
3. Locate the **Boot** or **System Configuration** tab:
   * Set the **Boot Mode** to **UEFI Only** or **Native UEFI**.
   * Set **CSM (Compatibility Support Module)** or **Legacy Support** to **Disabled**.
   * Locate **Fast Boot** or **Quick Boot** and set it to **Disabled** (forcing complete POST diagnostics and full TPM initialization on every boot).
   * Locate the **Boot Order / Priority**:
     * Set the primary internal storage drive (Windows Boot Manager) as the first and only boot option.
     * Disable secondary boot sources (USB, CD/DVD, PXE Network Boot) or require the UEFI administrator password for boot override menus (typically accessed via F12).
4. Navigate to the **Advanced**, **CPU Configuration**, or **Security Chip** section:
   * Locate **Intel Virtualization Technology (VT-x)** or **AMD-V** and set it to **Enabled**.
   * Locate **Intel VT for Directed I/O (VT-d)** or **AMD IOMMU** and set it to **Enabled** (required for IOMMU/Kernel DMA Protection).
   * Locate **TPM 2.0 Device** (or **Security Chip / Intel PTT / AMD fTPM**) and set it to **Enabled** or **Active** (with SHA-256 PCR bank).
   * Locate **Memory Overwrite Request Control Lock** (or **MOR Lock**) and set it to **Enabled**.
5. Navigate to the **Security** or **Secure Boot** section:
   * Ensure **Secure Boot** is **Enabled** and the **Secure Boot Mode** is set to **Deployed** or **User Mode**.
   * Harden the certificates allowlist:
     * **Key Exchange Key (KEK)**: Must only contain "Microsoft Corporation KEK CA 2011" and "Microsoft Corporation KEK 2K CA 2023".
     * **Signature Database (db)**: Must only contain "Microsoft Windows Production PCA 2011" and "Windows UEFI CA 2023". Remove "Microsoft UEFI CA 2011" and "Microsoft Option ROM UEFI CA 2023" unless strictly required by specific physical PCIe expansion hardware.
6. Navigate to the **Advanced** or **Firmware Update** section:
   * Locate the option for **BIOS Flash Protection** or **Firmware Rollback Protection** and set it to **Enabled** or **Block Downgrades**.
7. Save settings and exit the utility.

#### 2. Programmatic Configuration (Enterprise Deployment)
Use OEM utilities to deploy the UEFI password and boot configuration:
* **Dell Systems**: Use Dell Command | Configure (`cctk.exe`):
```cmd
cctk.exe --setuppwd=YourSecureEnterpriseBIOSPassword
cctk.exe --bootorder=hdd
cctk.exe --legacydevorder=
cctk.exe --embuefipxe=disable
cctk.exe --virtualization=enable
cctk.exe --vt-d=enable
cctk.exe --fastboot=disable
cctk.exe --mor=enable
```
* **HP Systems**: Use HP Client Management Script Library (CMSL) in PowerShell:
```powershell
Set-HPBiosSettingValue -Setting "Set BIOS Administrator Password" -Value "YourSecureEnterpriseBIOSPassword"
Set-HPBiosSettingValue -Setting "Configure Legacy Boot" -Value "Disable"
Set-HPBiosSettingValue -Setting "Boot Order" -Value "Hard Drive"
Set-HPBiosSettingValue -Setting "Virtualization Technology (VTx)" -Value "Enable"
Set-HPBiosSettingValue -Setting "Virtualization Technology Directed I/O (VTd)" -Value "Enable"
Set-HPBiosSettingValue -Setting "Fast Boot" -Value "Disable"
Set-HPBiosSettingValue -Setting "Memory Overwrite Request" -Value "Enable"
```

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

While hardware firmware settings cannot be directly written via standard Windows registry keys, the current state of the local UEFI boot environment and system BIOS characteristics can be programmatically audited.

Run the following script to verify native UEFI boot, Secure Boot state, and retrieve system BIOS properties:

[Download Script: Audit-UEFISecurity.ps1](audit_scripts/Audit-UEFISecurity.ps1)

```powershell
# Audit-UEFISecurity.ps1
# Description: Audits local boot environment and BIOS firmware properties.

Write-Host "--- Auditing UEFI Security Baseline ---" -ForegroundColor Cyan

# 1. Verify boot environment type
$RegPath = "HKLM:\System\CurrentControlSet\Control"
$FirmwareProperty = Get-ItemProperty -Path $RegPath -Name "PEFirmwareType" -ErrorAction SilentlyContinue

if ($FirmwareProperty) {
    $FirmwareValue = $FirmwareProperty.PEFirmwareType
    if ($FirmwareValue -eq 2) {
        Write-Host "Status: Native UEFI mode is active." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: System booted in Legacy BIOS mode (CSM enabled). Value: $($FirmwareValue)" -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: Boot environment type could not be read from registry." -ForegroundColor Red
}

# 2. Audit Secure Boot status
try {
    $SecureBootActive = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SecureBootActive -eq $true) {
        Write-Host "Status: UEFI Secure Boot is enabled." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: UEFI Secure Boot is supported but disabled in firmware." -ForegroundColor Red
    }
} catch [System.PlatformNotSupportedException] {
    Write-Host "VULNERABLE: UEFI Secure Boot is not supported on this platform." -ForegroundColor Red
} catch {
    Write-Host "VULNERABLE: UEFI Secure Boot validation failed. Error: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Retrieve BIOS details
$BiosDetails = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
if ($BiosDetails) {
    Write-Host "Firmware Manufacturer: $($BiosDetails.Manufacturer)" -ForegroundColor White
    Write-Host "Firmware Version: $($BiosDetails.SMBIOSBIOSVersion)" -ForegroundColor White
    Write-Host "Firmware Release Date: $($BiosDetails.ReleaseDate)" -ForegroundColor White
} else {
    Write-Host "Warning: BIOS details could not be retrieved via WMI." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (Device Guard/VBS prerequisites)
* **Microsoft Security Guidelines**: UEFI Firmware Security and Device Guard Deployment
