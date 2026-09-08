# [REQ-END-013] UEFI Firmware Security Hardening

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-005](../07-paws/configure-uefi-security.md); for Domain Controllers, refer to [REQ-DC-157](../02-domain-controllers/configure-uefi-security.md)).*
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

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
    * `RequirePlatformSecurityFeatures` = `1` or `3` (REG_DWORD)

---

## Rationale
Standard Tier 2 endpoints (such as corporate laptops and desktop workstations) and member servers are frequently exposed to physical theft, unauthorized local access in branch offices, or untrusted local networks. If system firmware remains unconfigured or relies on legacy BIOS modes, attackers can alter boot settings, subvert operating system security features, bypass disk encryption, or execute physical DMA and bootkit attacks.

### 1. Threats to Fleet Firmware Security
* **Bootkit and Pre-Boot Persistence**: Vulnerabilities in older bootloaders or unsigned EFI modules can be exploited by malware to gain persistence below the operating system. Without Secure Boot and native UEFI enforcement, an attacker with physical access or local administrator privileges can compromise the OS loader before security agents initialize.
* **Firmware Password Absence**: If firmware setup is unprotected, anyone with physical access can enter BIOS setup, disable Secure Boot, disable the TPM chip, enable legacy boot (CSM), and boot unauthorized diagnostic tools or alternative operating systems from USB.
* **Direct Memory Access (DMA) Attacks**: Modern laptops equipped with high-speed expansion interfaces (Thunderbolt, USB4, PCIe) are vulnerable to DMA attacks where hardware peripherals read volatile RAM. Enabling IOMMU (VT-d / AMD-Vi) at the firmware level provides the hardware foundation for Windows Kernel DMA Protection.
* **Firmware Downgrade Attacks**: If firmware rollback protection is disabled, an attacker can flash an older, vulnerable BIOS revision that contains known security flaws or bypasses.

### 2. Standard Endpoint & Member Server Firmware Baseline
Securing firmware across an enterprise fleet requires balancing strict hardware protections with fleet manageability:
1. **UEFI Administrator Password**: Enforce a strong supervisor/administrator password across all fleet endpoints. Centralized password lifecycle management should be automated using vendor enterprise tools (e.g., Dell Command | PowerShell Provider, HP Client Management Script Library, Lenovo ThinkManagement WMI, or Microsoft Surface Enterprise Management Mode).
2. **Native UEFI Boot Mode (CSM Disabled)**: Enforce pure Native UEFI boot and disable Legacy BIOS/CSM. Native UEFI is required for UEFI Secure Boot, TPM 2.0 measurements, and Virtualization-Based Security (VBS).
3. **Boot Order Prioritization**: Prioritize the internal OS drive as the primary boot source. Password-protect the boot override menu (F12/F8) to prevent unauthorized booting from USB or secondary media, while allowing managed network PXE boot in staging environments if required.
4. **Fast Startup Optimization**: Disabling Windows Fast Startup (`HiberbootEnabled = 0`) ensures full hardware initialization and cold-boot integrity measurements on every startup.
5. **Hardware Virtualization & DMA Security**: Enable CPU Virtualization (VT-x / AMD-V) and IOMMU (VT-d / AMD-Vi) across all fleet systems to support Windows Hypervisor-Protected Code Integrity (HVCI), Credential Guard, and Kernel DMA Protection.
6. **TPM 2.0 Cryptoprocessor**: Ensure TPM 2.0 is active and ready, providing hardware storage for BitLocker keys and credential sealing.
7. **Secure Boot Enforcement**: Ensure UEFI Secure Boot is active in Deployed Mode with valid signature databases.
8. **Firmware Rollback Protection**: Enable BIOS write protection and block downgrades to older firmware revisions.

---

## Legacy Impact & Compatibility
* **Fleet Management Overhead**: Technicians must provide the supervisor password to enter BIOS settings or perform hardware diagnostics. This is managed via enterprise OEM automation or centralized password vaults.
* **Legacy MBR Disks**: Converting systems installed under Legacy BIOS (CSM) to UEFI requires repartitioning disks from MBR to GPT using `MBR2GPT.exe`. Operating systems that do not support UEFI cannot start.
* **Staged Deployment Considerations**: In environments utilizing network PXE boot for automated OS re-imaging (SCCM, MECM, MDT), PXE boot should be secured using 802.1X network authentication and restricted to dedicated imaging subnets.

---

## Pre-Deployment Verification

Execute the following PowerShell commands on the endpoint to inspect current boot mode, Secure Boot state, and TPM readiness:

```powershell
# Check firmware type, Secure Boot, and TPM status
$BootMode = $env:firmware_type
$SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$Tpm = Get-Tpm -ErrorAction SilentlyContinue

[PSCustomObject]@{
    BootMode      = $BootMode
    SecureBoot    = $SecureBoot
    TpmPresent    = $Tpm.TpmPresent
    TpmReady      = $Tpm.TpmReady
    Manufacturer  = (Get-CimInstance -ClassName Win32_Bios).Manufacturer
    BIOSVersion   = (Get-CimInstance -ClassName Win32_Bios).SMBIOSBIOSVersion
} | Format-List
```

---

## Implementation Steps

### Option A: Manual UEFI Firmware Configuration (Preferred)

UEFI settings must be configured directly within the hardware platform firmware interface during system startup.

1. Turn on or restart the workstation and access the UEFI utility screen by pressing the vendor-specific key during POST (typically Delete, F2, F10, or F12).
2. Navigate to the **Security** or **Authentication** section:
   * Select the option to set the **Administrator Password** (also referred to as the **Supervisor Password**). Do not configure a User Password, as that prompts for authentication on every boot rather than only when entering configuration settings.
   * Enter a strong, complex password. Record this password in the enterprise credential vault.
3. Navigate to the **Boot** or **System Configuration** section:
   * Locate the **Boot Mode** setting and set it to **UEFI Only** or **Native UEFI**.
   * Locate **CSM (Compatibility Support Module)** or **Legacy Boot Support** and set it to **Disabled**.
   * Locate **Fast Boot** or **Quick Boot** and set it to **Disabled** (forcing complete POST diagnostics and full TPM initialization on every boot).
   * Locate **Boot Order** (or **Boot Priority**):
     * Set the primary boot option to the internal system storage drive (typically containing the Windows Boot Manager partition).
     * Disable unauthorized external boot devices (such as optical drives and unauthorized USB boot) or require the administrator password to boot from alternate media.
     * Enable the option to prompt for the UEFI administrator password if a user attempts to access the boot override menu (typically F12 or F8).
4. Navigate to the **Advanced**, **CPU Configuration**, or **Security Chip** section:
   * Locate **Intel Virtualization Technology (VT-x)** or **AMD-V** and set it to **Enabled**.
   * Locate **Intel VT for Directed I/O (VT-d)** or **AMD IOMMU** and set it to **Enabled** (required for IOMMU/Kernel DMA Protection).
   * Locate **TPM 2.0 Device** (or **Security Chip / Intel PTT / AMD fTPM**) and set it to **Enabled** or **Active** (with SHA-256 PCR bank).
5. Navigate to the **Security** or **Secure Boot** section:
   * Ensure **Secure Boot** is **Enabled** and the **Secure Boot Mode** is set to **Deployed** or **User Mode**.
6. Navigate to the **Advanced** or **Firmware Update** section:
   * Locate the option for **BIOS Flash Protection** or **Firmware Rollback Protection** and set it to **Enabled** or **Block Downgrades**.
7. Save the configuration and restart the workstation.

---

### Option B: PowerShell Remediation & OS Boot Hardening

Run the following script to configure OS-level boot parameters (disabling Windows Fast Startup, ensuring Device Guard platform flags), detect the hardware vendor, and provide enterprise OEM automation commands.

[Download Script: Set-UEFISecurity.ps1](implementation_scripts/Set-UEFISecurity.ps1)

```powershell
# Set-UEFISecurity.ps1
# Description: Configures OS-level boot parameters and audits OEM firmware configuration for endpoints and member servers.

Write-Host "--- Configuring Endpoint UEFI & Boot Security Baseline ---" -ForegroundColor Cyan

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

# 2. Configure Device Guard Platform Security Flags
$DeviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

try {
    # 1 = Secure Boot, 3 = Secure Boot and DMA Protection
    Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force -ErrorAction Stop
    Write-Host "[+] Device Guard required platform security features configured (Value = 1)." -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to configure RequirePlatformSecurityFeatures: $($_.Exception.Message)" -ForegroundColor Red
}

# 3. Detect Hardware OEM and report vendor tooling commands
$Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue
Write-Host "`nOEM Firmware Detection:" -ForegroundColor Cyan
Write-Host "  Manufacturer: $($Bios.Manufacturer)" -ForegroundColor White
Write-Host "  BIOS Version: $($Bios.SMBIOSBIOSVersion)" -ForegroundColor White

if ($Bios.Manufacturer -match "Dell") {
    Write-Host "  [i] Dell Platform detected. Enterprise configuration via Dell Command | PowerShell Provider:" -ForegroundColor Yellow
    Write-Host "      Import-Module DellBIOSProvider" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\Boot\BootMode 'UEFI'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\SecureBoot\SecureBoot 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\Virtualization 'Enabled'" -ForegroundColor Gray
    Write-Host "      Set-Item -Path DellSmbios:\VirtualizationSupport\VtForDirectIO 'Enabled'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "HP") {
    Write-Host "  [i] HP Platform detected. Enterprise configuration via HP Client Management Script Library (HPCMSL):" -ForegroundColor Yellow
    Write-Host "      Import-Module HPCMSL" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Boot Mode' -Value 'UEFI Native (without CSM)'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Secure Boot' -Value 'Enable'" -ForegroundColor Gray
    Write-Host "      Set-HPBIOSSettingValue -Name 'Virtualization Technology' -Value 'Enable'" -ForegroundColor Gray
} elseif ($Bios.Manufacturer -match "Lenovo") {
    Write-Host "  [i] Lenovo Platform detected. Enterprise configuration via Lenovo BIOS WMI interface:" -ForegroundColor Yellow
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('BootMode,UEFI')" -ForegroundColor Gray
    Write-Host "      (gwmi -class Lenovo_SetBiosSetting -namespace root\wmi).SetBiosSetting('SecureBoot,Enable')" -ForegroundColor Gray
}

Write-Host "`n[+] Remediation script completed." -ForegroundColor Green
```

---

## Auditing & Verification

### PowerShell Audit Script

Run the following script to verify native UEFI boot mode, Secure Boot status, TPM 2.0 state, CPU virtualization, and Windows Fast Startup configuration across endpoints.

[Download Script: Audit-UEFISecurity.ps1](audit_scripts/Audit-UEFISecurity.ps1)

```powershell
# Audit-UEFISecurity.ps1
# Description: Audits local boot environment, Secure Boot, TPM, virtualization, and BIOS firmware properties for endpoints.

Write-Host "--- Auditing UEFI Security Baseline for Endpoints ---" -ForegroundColor Cyan

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

# 5. Audit Windows Fast Startup Configuration
$PowerReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -ErrorAction SilentlyContinue
if ($PowerReg -and $PowerReg.HiberbootEnabled -eq 0) {
    Write-Host "  [+] Windows Fast Startup: Disabled (Full cold boot enforced)." -ForegroundColor Green
} else {
    Write-Host "  [!] VULNERABLE: Windows Fast Startup is enabled (HiberbootEnabled != 0). Must be disabled for deterministic boot measurements." -ForegroundColor Red
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
Firmware and boot configuration events are logged across standard Windows event logs:
* **Microsoft-Windows-Kernel-Boot**:
  * **Event ID 20**: Records firmware boot mode (Native UEFI vs Legacy BIOS).
  * **Event ID 32**: Records Secure Boot operational state during bootloader verification.
* **Microsoft-Windows-DeviceGuard/Operational**:
  * **Event ID 7000**: Virtualization-Based Security initialization and hardware requirements validation.
* **System Event Log (EventLog-BitLocker)**:
  * **Event ID 785**: BitLocker TPM and PCR measurements validation.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (Device Guard/Virtualization-Based Security prerequisites)
* **ANSSI AD Hardening Guide**: Operational baseline recommendations regarding hardware platform integrity.
* **DoD Windows 10/11 STIG**: Rule `V-220745` (UEFI Secure Boot and Firmware Configuration)
* **Microsoft Security Guidelines**: UEFI Firmware Security and Hardware-Rooted Security Deployment
