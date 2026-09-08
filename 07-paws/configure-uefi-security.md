# [REQ-PAW-005] UEFI Firmware Security Hardening

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Domain Controllers, refer to [REQ-DC-157](../02-domain-controllers/configure-uefi-security.md); for Tier 2 Client Workstations and Member Servers, refer to [REQ-END-013](../08-endpoints/configure-uefi-security.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware Configuration Menu (Hardware Level)
  * `HKLM\SYSTEM\CurrentControlSet\Control`
    * `PEFirmwareType` = `2` (REG_DWORD)
  * `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`
    * `UEFISecureBootEnabled` = `1` (REG_DWORD)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power`
    * `HiberbootEnabled` = `0` (REG_DWORD)
  * `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
    * `RequirePlatformSecurityFeatures` = `3` (REG_DWORD)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated administrative bastions that operate at the pinnacle of the enterprise security architecture (Tier 0). Compromise of a PAW grants adversaries the credentials necessary to commandeer identity infrastructure, cloud tenants, and enterprise directory data.

If an attacker obtains physical access to a PAW, or if malicious code gains low-level administrative control, vulnerabilities in the boot chain or legacy firmware interfaces can be exploited to bypass operating system security boundaries, defeat BitLocker disk encryption, or implant persistent firmware bootkits before the Windows kernel loads.

### 1. Threats to Pre-Boot Firmware Integrity
* **Firmware Rootkits & Bootkits**: Adversaries deploy firmware-level implants (e.g., BlackLotus, ESPecter, MoonBounce) that execute within the Extensible Firmware Interface (EFI) environment before Windows boot files (`bootmgr.efi`, `winload.efi`) initialize. Once established in Ring -2 (System Management Mode - SMM) or Ring -1 (Hypervisor), an implant can disable Virtualization-Based Security (VBS), patch kernel functions, and blind Endpoint Detection and Response (EDR) agents.
* **Physical DMA Exploitation**: External peripheral ports (Thunderbolt, USB4, PCIe) with direct memory access allow rogue devices to read and write physical memory before the OS initializes its IOMMU mappings, enabling direct extraction of cryptographic keys and BitLocker volume master keys.
* **Cold-Boot Memory Extraction**: Resetting or power-cycling a workstation can leave encryption secrets in volatile DRAM. Enabling the Memory Overwrite Request (MOR) lock forces firmware to sanitize memory during unexpected reboots, preventing memory-remanence key harvesting.
* **Boot Device Hijacking**: If external media boot is permitted, an attacker with physical access can insert a live USB containing password-reset tools, Linux distributions, or forensic memory dumpers to access storage drives offline.

### 2. Tightened PAW Firmware Security Baseline
Standard client workstations often maintain flexibility for diverse legacy peripherals, network booting during staging, or third-party operating systems. On dedicated Tier 0 PAWs, this baseline is intentionally **tightened**:
1. **Firmware Lockdown & Password Protection**: Enforcing a strong, vaulted UEFI supervisor/administrator password prevents unauthorized physical tampering with hardware configurations (such as disabling TPM 2.0, Secure Boot, or virtualization extensions). The boot menu override key (F12/F8) must also be password-protected.
2. **Native UEFI Boot Mode (CSM Disabled)**: Disabling the Compatibility Support Module (CSM) or Legacy BIOS options forces pure Native UEFI mode, which is an architectural pre-requisite for UEFI Secure Boot, TPM measurements, and Virtualization-Based Security (VBS).
3. **Strict Boot Order Lockdown**: The firmware boot sequence is restricted exclusively to the primary internal NVMe/SSD OS storage drive. Network PXE boot, USB storage boot, external optical drive boot, and removable media boot are completely disabled in firmware to prevent offline operating system execution.
4. **Disabling Fast Boot and Windows Fast Startup**: Disabling Fast Boot in firmware and Windows Fast Startup (`HiberbootEnabled = 0`) forces full hardware initialization, device self-tests, memory sanitization, and deterministic TPM PCR 0-7 measurements on every boot. This prevents residual boot state reuse across administrative sessions.
5. **Virtualization and DMA Protection Foundation**: Enabling CPU Virtualization Extensions (Intel VT-x / AMD-V) and IOMMU (Intel VT-d / AMD-Vi) at the firmware level establishes the mandatory hardware isolation required by the Windows Hypervisor to run VBS, Credential Guard, and Kernel DMA Protection.
6. **TPM 2.0 and SHA-256 PCR Bank**: Ensuring TPM 2.0 is active with the SHA-256 PCR bank enables hardware-rooted platform attestation and BitLocker sealing.
7. **Hardened Secure Boot Signature Database (`db`)**: The Secure Boot signature database (`db`) is tightened on PAWs to remove third-party UEFI Certificate Authorities ("Microsoft UEFI CA 2011" and "Microsoft Option ROM UEFI CA 2023"). Dedicated PAWs must boot only Microsoft Windows Production PCA binaries, preventing the execution of third-party bootloaders or vulnerable Linux shims.
8. **Firmware Rollback Protection**: Enabling BIOS Flash Protection and Firmware Rollback Protection blocks attackers from flashing older, vulnerable BIOS revisions containing known vulnerabilities.

---

## Legacy Impact & Compatibility
* **Administrative Maintenance**: Technicians must enter the UEFI supervisor password to modify hardware configurations, update firmware, or perform diagnostics. This password must be generated with high entropy and stored securely in the enterprise Tier 0 Privileged Access Management (PAM) vault.
* **Offline Boot Media Incompatibility**: Disabling USB and PXE boot prevents booting administrative diagnostics or custom recovery media directly from USB keys. Re-imaging or recovery of a PAW requires booting into authorized Windows Recovery Environment (WinRE) or temporarily entering the UEFI supervisor password to re-enable boot media during controlled maintenance.
* **Partition Style Pre-requisite**: Native UEFI requires the primary OS storage drive to use GUID Partition Table (GPT). Legacy Master Boot Record (MBR) disks must be converted using `MBR2GPT.exe` prior to switching firmware to Native UEFI mode.

---

## Pre-Deployment Verification

Execute the following PowerShell commands on the PAW to inspect the current boot mode, Secure Boot state, and TPM readiness:

```powershell
# Verify Native UEFI, Secure Boot, and TPM 2.0 readiness
$Firmware = $env:firmware_type
$SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$Tpm = Get-Tpm -ErrorAction SilentlyContinue

[PSCustomObject]@{
    BootMode       = $Firmware
    SecureBoot     = $SecureBoot
    TpmPresent     = $Tpm.TpmPresent
    TpmReady       = $Tpm.TpmReady
    Manufacturer   = (Get-CimInstance -ClassName Win32_Bios).Manufacturer
    SMBIOSVersion  = (Get-CimInstance -ClassName Win32_Bios).SMBIOSBIOSVersion
} | Format-List
```

---

## Implementation Steps

### Option A: Manual UEFI Firmware Configuration (Preferred)

UEFI settings must be configured directly within the hardware platform firmware interface during system startup.

1. Turn on or restart the workstation and access the UEFI setup utility by pressing the vendor-specific key during POST (typically Delete, F2, F10, or F12).
2. Navigate to the **Security** or **Authentication** section:
   * Select the option to set the **Administrator Password** (also referred to as the **Supervisor Password**). Do not configure a User Password, as that prompts for authentication on every boot rather than only when entering configuration settings.
   * Enter a strong, complex password. Record this password in the enterprise Tier 0 credential vault.
3. Navigate to the **Boot** or **System Configuration** section:
   * Locate the **Boot Mode** setting and set it to **UEFI Only** or **Native UEFI**.
   * Locate **CSM (Compatibility Support Module)** or **Legacy Boot Support** and set it to **Disabled**.
   * Locate **Fast Boot** or **Quick Boot** and set it to **Disabled** (forcing complete POST diagnostics and full TPM initialization on every boot).
   * Locate **Boot Order** (or **Boot Priority**):
     * Set the primary boot option to the internal system storage drive (typically containing the Windows Boot Manager partition).
     * Disable all other boot options (such as USB, SD Card, Optical Drive, and Network PXE Boot) or set them to disabled in the boot menu.
     * Enable the option to prompt for the UEFI administrator password if a user attempts to access the boot override menu (typically F12 or F8).
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
7. Save the configuration and restart the workstation.

---

### Option B: PowerShell Remediation & OS Boot Hardening

Run the following script to configure OS-level boot parameters (disabling Windows Fast Startup, ensuring memory protections), audit OEM firmware capabilities, and guide hardware-level configuration.

[Download Script: Set-PawUEFISecurity.ps1](implementation_scripts/Set-PawUEFISecurity.ps1)

```powershell
# Set-PawUEFISecurity.ps1
# Description: Configures OS-level boot parameters and audits OEM firmware configuration for PAWs.

Write-Host "--- Configuring PAW UEFI & Boot Security Baseline ---" -ForegroundColor Cyan

# 1. Disable Windows Fast Startup (forces full cold boot and fresh TPM PCR measurements)
$PowerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
if (-not (Test-Path $PowerPath)) {
    New-Item -Path $PowerPath -Force | Out-Null
}

try {
    Set-ItemProperty -Path $PowerPath -Name "HiberbootEnabled" -Value 0 -Type DWord -Force -ErrorAction Stop
    Write-Host "[+] Windows Fast Startup disabled (HiberbootEnabled = 0)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure HiberbootEnabled: $($_.Exception.Message)" -ForegroundColor Red
}

# 2. Configure Device Guard Platform Security Flags (Requires UEFI and Secure Boot)
$DeviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

try {
    # 1 = Secure Boot, 2 = DMA Protection, 3 = Secure Boot and DMA Protection
    Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Force -ErrorAction Stop
    Write-Host "[+] Device Guard required platform security features set to Secure Boot and DMA Protection (Value = 3)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure RequirePlatformSecurityFeatures: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Detect Hardware OEM and report vendor tooling commands
$Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
Write-Host "`nOEM Firmware Detection:" -ForegroundColor Cyan
Write-Host "  Manufacturer: $($Bios.Manufacturer)" -ForegroundColor White
Write-Host "  BIOS Version: $($Bios.SMBIOSBIOSVersion)" -ForegroundColor White

if ($Bios.Manufacturer -match "Dell") {
    Write-Host "  [i] Dell Platform detected. To enforce UEFI settings via Dell Command | PowerShell Provider:" -ForegroundColor Yellow
    Write-Host "      Import-Module DellBIOSProvider" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\Security\AdminPassword 'YourStrongPassword'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\Boot\BootMode 'UEFI'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\SecureBoot\SecureBoot 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\Virtualization 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\VtForDirectIO 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\PostBehavior\Fastboot 'Thorough'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "HP") {
    Write-Host "  [i] HP Platform detected. To enforce UEFI settings via HP Client Management Script Library (HPCMSL):" -ForegroundColor Yellow
    Write-Host "      Import-Module HPCMSL" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Boot Mode' -Value 'UEFI Native (without CSM)'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Secure Boot' -Value 'Enable'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Fast Boot' -Value 'Disable'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Virtualization Technology' -Value 'Enable'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Virtualization Technology for Directed I/O' -Value 'Enable'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "Lenovo") {
    Write-Host "  [i] Lenovo Platform detected. To enforce UEFI settings via Lenovo BIOS WMI interface:" -ForegroundColor Yellow
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('BootMode,UEFI')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('SecureBoot,Enable')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('IntelVirtualizationTechnology,Enable')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('VTd,Enable')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SaveBiosSettings -namespace root\wmi).SaveBiosSettings()" -ForegroundColor Gray
}

Write-Host "`n[+] Remediation script completed." -ForegroundColor Green
```

---

## Auditing & Verification

### PowerShell Audit Script

Run the following script to verify the native boot mode, Secure Boot status, TPM 2.0 readiness, CPU virtualization, IOMMU protection, and Windows Fast Startup configuration.

[Download Script: Audit-UEFISecurity.ps1](audit_scripts/Audit-UEFISecurity.ps1)

```powershell
# Audit-UEFISecurity.ps1
# Description: Audits local boot environment, Secure Boot, TPM, virtualization, and BIOS firmware properties for PAWs.

Write-Host "--- Auditing UEFI Security Baseline for PAWs ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# 1. Verify Boot Environment Type (Native UEFI)
$FirmwareType = $env:firmware_type
$RegPath = "HKLM:\System\CurrentControlSet\Control"
$FirmwareProperty = Get-ItemProperty -Path $RegPath -Name "PEFirmwareType" -ErrorAction SilentlyContinue

if ($FirmwareProperty -and $FirmwareProperty.PEFirmwareType -eq 2) {
    Write-Host "  [+] Boot Mode: Native UEFI active (PEFirmwareType = 2)." -ForegroundColor Green
} elseif ($FirmwareType -eq "UEFI") {
    Write-Host "  [+] Boot Mode: Native UEFI active (firmware_type = UEFI)." -ForegroundColor Green
} else {
    Write-Host "  [!] VULNERABLE: System booted in Legacy BIOS mode (CSM enabled) or unrecognized firmware type." -ForegroundColor Red
    $script:Vulnerable = $true
}

# 2. Audit UEFI Secure Boot Status
try {
    $SecureBootActive = Confirm-SecureBootUEFI -ErrorAction Stop
    if ($SecureBootActive -eq $true) {
        Write-Host "  [+] Secure Boot: Enabled in firmware." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: Secure Boot is supported but currently disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
} catch [System.PlatformNotSupportedException] {
    Write-Host "  [!] VULNERABLE: UEFI Secure Boot is not supported on this platform." -ForegroundColor Red
    $script:Vulnerable = $true
} catch {
    Write-Host "  [!] VULNERABLE: UEFI Secure Boot validation failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 3. Audit TPM 2.0 Status
try {
    $Tpm = Get-Tpm -ErrorAction Stop
    if ($Tpm.TpmPresent -and $Tpm.TpmReady) {
        Write-Host "  [+] TPM 2.0: Present and Ready (Enabled: $($Tpm.TpmEnabled), Activated: $($Tpm.TpmActivated))." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: TPM is not present, not ready, or disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
} catch {
    Write-Host "  [!] VULNERABLE: Failed to query TPM status: $($_.Exception.Message)" -ForegroundColor Red
    $script:Vulnerable = $true
}

# 4. Audit CPU Virtualization Extensions in Firmware
$Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
if ($Processor -and $Processor.VirtualizationFirmwareEnabled -eq $true) {
    Write-Host "  [+] Hardware Virtualization: Enabled in firmware (VT-x / AMD-V)." -ForegroundColor Green
} else {
    # If Hyper-V/VBS is already running, VirtualizationFirmwareEnabled may report false inside partition
    $Vbs = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
    if ($Vbs -and $Vbs.VirtualizationBasedSecurityStatus -ge 1) {
        Write-Host "  [+] Hardware Virtualization: Verified active via running Virtualization-Based Security." -ForegroundColor Green
    } else {
        Write-Host "  [!] VULNERABLE: Hardware CPU virtualization extensions are disabled in firmware." -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

# 5. Audit Windows Fast Startup Configuration (Must be disabled)
$PowerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
if ($PowerReg -and $PowerReg.HiberbootEnabled -eq 0) {
    Write-Host "  [+] Windows Fast Startup: Disabled (Full cold boot enforced)." -ForegroundColor Green
} else {
    Write-Host "  [!] VULNERABLE: Windows Fast Startup is enabled (HiberbootEnabled != 0). Must be disabled on PAWs." -ForegroundColor Red
    $script:Vulnerable = $true
}

# 6. Retrieve BIOS Firmware Specifications
$BiosDetails = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
if ($BiosDetails) {
    Write-Host "  Firmware Manufacturer: $($BiosDetails.Manufacturer)" -ForegroundColor White
    Write-Host "  Firmware Version:      $($BiosDetails.SMBIOSBIOSVersion)" -ForegroundColor White
    Write-Host "  Firmware Release Date: $($BiosDetails.ReleaseDate)" -ForegroundColor White
} else {
    Write-Host "  Warning: BIOS details could not be retrieved via WMI." -ForegroundColor Yellow
}

# Final Verdict
if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Auditing, Detection & Telemetry
Firmware and boot security telemetry is recorded in Windows event channels:
* **Microsoft-Windows-Kernel-Boot**:
  * **Event ID 20**: Boot mode type (UEFI vs PC-AT legacy).
  * **Event ID 32**: Secure Boot state recorded at boot transition.
* **Microsoft-Windows-DeviceGuard/Operational**:
  * **Event ID 7000**: Virtualization-Based Security initialization and hardware requirements validation.
* **Microsoft-Windows-TPM-WMI**:
  * **Event ID 1024**: TPM driver initialization and cryptographic operational status.
* **System Event Log (EventLog-BitLocker)**:
  * **Event ID 785**: BitLocker successfully sealed or unsealed volume keys using TPM and PCR measurements.

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R58 (Use of Privileged Access Workstations)
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (Device Guard and Virtualization-Based Security Prerequisites)
* **DoD Windows 10/11 STIG**: Rule `V-220745` (UEFI Secure Boot and Firmware Lockdown Requirements)
* **Microsoft Security Guidelines**: Securing Privileged Access Workstations (PAW Hardening Guidance)
