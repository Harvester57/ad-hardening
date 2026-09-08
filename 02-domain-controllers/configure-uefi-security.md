# [REQ-DC-157] UEFI Firmware Security Hardening on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (both physical bare-metal enterprise servers and hypervisor-hosted virtual machines). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-005](../07-paws/configure-uefi-security.md); for Tier 2 Client Workstations and Member Servers, refer to [REQ-END-013](../08-endpoints/configure-uefi-security.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware Configuration Menu (Hardware Level / Hypervisor Level)
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
Domain Controllers are Tier 0 crown jewels that store the directory database (`NTDS.dit`), Kerberos key distribution services (`KDC`), and enterprise authentication secrets. If the underlying platform firmware or virtual machine boot configuration is compromised, an attacker can subvert all operating system and hypervisor defenses before the Windows kernel loads.

### 1. Threats to Domain Controller Platform Integrity
* **Firmware Rootkits & Bootkits**: Attackers deploying UEFI bootkits (e.g., BlackLotus, ESPecter) subvert the Windows bootloader (`winload.efi`) and initialize malicious code before LSASS or endpoint protection software starts. This grants adversaries Ring 0 execution privileges capable of bypassing Protected Process Light (PPL), dumping NTDS secrets, or establishing persistent hypervisor implants.
* **Unauthorized Boot Media Execution**: If external boot devices or network PXE boots are enabled in production, an attacker with physical or out-of-band console access can boot the server into an alternate operating system (e.g., Linux live distribution or forensic environment) to extract `NTDS.dit` and the `SYSTEM` registry hive directly from unencrypted disks.
* **Direct Memory Access (DMA) & Cold-Boot Exploitation**: High-speed peripheral expansion buses (PCIe, NVMe, Thunderbolt) can be exploited via malicious DMA controllers to read RAM contents. Furthermore, resetting physical server hardware without memory sanitization leaves transient encryption keys in DRAM. Enabling the Memory Overwrite Request (MOR) lock forces firmware to sanitize memory during unexpected power cycles. *(For operating system and registry-level DMA mitigation policies, refer to [REQ-DC-158](harden-dma-and-physical-security.md)).*
* **Out-of-Band Management Controller (BMC) Attacks**: Enterprise servers rely on Baseboard Management Controllers (Dell iDRAC, HPE iLO, Lenovo XClarity, Cisco CIMC). If BMCs expose legacy protocols (e.g., IPMI over LAN with cipher 0 vulnerabilities), use weak credentials, or permit unauthenticated Virtual Media (vMedia) mounting, attackers can remotely compromise firmware or mount malicious boot ISOs without physical data center access.
* **Virtualization Boundary Compromise**: In virtualized environments, running Domain Controllers as legacy Generation 1 / BIOS virtual machines exposes the domain to hypervisor-level bootloader replacement, lacks vTPM integration, and prevents the activation of Virtualization-Based Security (VBS) and Credential Guard.

### 2. Domain Controller Firmware Security Baseline

#### A. Physical Bare-Metal Domain Controllers
1. **UEFI Supervisor Password**: Enforce a strong, complex supervisor/administrator password on physical server firmware. Store this password in the enterprise Tier 0 credential repository. The boot override menu (e.g., F11/F12) must require the supervisor password.
2. **Native UEFI Boot Mode (CSM Disabled)**: Enforce pure Native UEFI boot and disable legacy BIOS / Compatibility Support Module (CSM).
3. **Disabling Fast Boot**: Force full hardware diagnostics, device memory self-tests, and complete TPM PCR 0-7 measurements on every server boot.
4. **Boot Order Lockdown**: Lock the primary boot sequence strictly to the internal RAID storage array containing the OS bootloader. Completely disable external USB boot, optical drive boot, and network PXE boot in production (PXE is permitted only during initial server provisioning on an isolated staging VLAN).
5. **Hardware Virtualization & IOMMU**: Enable Intel VT-x / AMD-V and Intel VT-d / AMD-Vi at the firmware level. This is mandatory for running Hyper-V, Virtualization-Based Security (VBS), and Kernel DMA Protection on Windows Server.
6. **TPM 2.0 Cryptoprocessor**: Ensure physical server TPM 2.0 is active with the SHA-256 PCR bank enabled.
7. **Memory Overwrite Request (MOR) Lock**: Enable MOR Lock to mitigate cold-boot memory extraction attacks.
8. **Secure Boot Enforcement**: Ensure UEFI Secure Boot is active in Deployed Mode with valid signature databases and current DBX revocations applied (refer to [REQ-DC-033](configure-secure-boot-revocations.md)).
9. **Firmware Rollback Protection**: Enable BIOS Flash Protection and Firmware Rollback Prevention to block downgrade attacks targeting known firmware vulnerabilities.
10. **Out-of-Band (BMC) Hardening**:
    * Isolate BMC management ports on a dedicated, non-routable Tier 0 out-of-band management network.
    * Disable legacy IPMI over LAN (UDP port 623) to eliminate cipher suite 0 and RAKP password hash extraction vulnerabilities.
    * Enforce HTTPS with TLS 1.2/1.3 and disable unencrypted HTTP redirection.
    * Disconnect and disable Virtual Media (vMedia) during normal production operations.

#### B. Virtual Domain Controllers (Hyper-V / VMware vSphere)
1. **Hyper-V Generation 2 VMs**: Deploy virtual Domain Controllers exclusively as Generation 2 VMs with UEFI firmware, Secure Boot enabled (using the "Microsoft Windows" template), and a Virtual TPM (vTPM) 2.0 device added.
2. **VMware vSphere EFI Firmware**: Configure the VM boot options to use **EFI** firmware with **Secure Boot** enabled and attach a Virtual TPM 2.0 device.
3. **Virtual Boot Order Lockdown**: Lock the VM boot order to the primary virtual hard disk (VHDX/VMDK). Disable network boot and disconnect virtual DVD/CD-ROM drives in production.
4. **Virtualization Host Security Boundary**: Ensure virtualization hosts hosting virtual Domain Controllers are hardened in accordance with Tier 0 isolation standards (refer to [REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](harden-dc-virtualization-hosts.md)).

---

## Legacy Impact & Compatibility
* **Maintenance Workflow**: Hardware technicians must obtain the supervisor password from the Tier 0 credential vault to alter BIOS settings or perform hardware diagnostics.
* **Legacy VM Migration**: Domain Controllers deployed as Generation 1 virtual machines (BIOS/MBR) cannot be dynamically converted to Generation 2 without rebuild or offline disk structure migration using `MBR2GPT.exe`. Environments with Generation 1 DC VMs should schedule structured DC promotions onto new Generation 2 VM deployments followed by graceful demotion of legacy instances.
* **Pre-Boot Deployment (PXE)**: Disabling network PXE boot in production prevents accidental or unauthorized network imaging. Staging and bare-metal OS provisioning must occur within dedicated provisioning networks before locking firmware down.

---

## Pre-Deployment Verification

Execute the following PowerShell commands on the Domain Controller to inspect current boot mode, Secure Boot state, and TPM readiness:

```powershell
# Inspect boot mode, Secure Boot, and TPM status on Domain Controller
$BootMode = $env:firmware_type
$SecureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
$Tpm = Get-Tpm -ErrorAction SilentlyContinue
$SystemModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model

[PSCustomObject]@{
    PlatformModel = $SystemModel
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

### Option A: Hardware & Hypervisor Firmware Configuration (Preferred)

#### For Physical Servers (Dell PowerEdge, HPE ProLiant, Lenovo ThinkSystem):
1. Restart the server and enter system setup during POST (typically F2 on Dell, F9 on HPE, F1 on Lenovo).
2. **Security Settings**:
   * Set a strong **System Password** / **Setup Password** (Administrator/Supervisor). Record it in the Tier 0 credential vault.
   * Verify **TPM 2.0 Security** is **Enabled** and **Activated** with SHA-256 PCR bank.
   * Enable **Memory Overwrite Request (MOR)** or Memory Clearing on boot.
3. **Boot Settings**:
   * Set **Boot Mode** to **UEFI**.
   * Disable **Legacy BIOS / CSM**.
   * Set **Boot Sequence** to primary internal storage (RAID/SAN). Disable USB and Network PXE boot options.
   * Enable password prompt on Boot Override Menu (F11/F12).
4. **Processor / Virtualization Settings**:
   * Enable **Intel Virtualization Technology (VT-x)** or **AMD-V**.
   * Enable **Intel VT for Directed I/O (VT-d)** or **AMD IOMMU**.
5. **Secure Boot Settings**:
   * Enable **Secure Boot**. Ensure Secure Boot Mode is set to **Deployed Mode**.
6. **Firmware Rollback**:
   * Enable **BIOS Flash Protection** / **Rollback Prevention**.
7. **Baseboard Management Controller (BMC / iDRAC / iLO)**:
   * Navigate to BMC network settings -> Disable **IPMI over LAN** (UDP 623).
   * Ensure web server enforces **HTTPS (TLS 1.2/1.3)**.
   * Detach and disable **Virtual Media**.

#### For Virtual Domain Controllers (Hyper-V Gen 2 / VMware ESXi):
* **Hyper-V**:
  1. Open **Hyper-V Manager**, select the Domain Controller VM, and open **Settings**.
  2. Navigate to **Security** -> check **Enable Secure Boot** (Template: **Microsoft Windows**).
  3. Under **Security Support**, check **Enable Trusted Platform Module** (vTPM).
  4. Navigate to **Firmware** -> verify boot order has the virtual hard drive (`.vhdx`) at the top, and remove network adapter and virtual DVD drive from the boot list.
* **VMware vSphere**:
  1. Open the **vSphere Client**, edit VM settings.
  2. Under **VM Options** -> **Boot Options** -> set Firmware to **EFI** and check **Enable UEFI Secure Boot**.
  3. Under **Virtual Hardware** -> click **Add New Device** -> select **Trusted Platform Module** (vTPM).
  4. Remove or disconnect virtual CD/DVD drives and disable network boot in VM boot options.

---

### Option B: PowerShell Remediation & OS Boot Hardening

Run the following script to configure OS-level boot parameters (disabling Windows Fast Startup, ensuring Device Guard platform flags), detect whether the Domain Controller is running on physical hardware or a virtual hypervisor, and display appropriate firmware configuration guidance.

[Download Script: Set-DcUefiSecurity.ps1](implementation_scripts/Set-DcUefiSecurity.ps1)

```powershell
# Set-DcUefiSecurity.ps1
# Description: Configures OS-level boot parameters and audits platform firmware configuration on Domain Controllers.

Write-Host "--- Configuring Domain Controller UEFI & Boot Security Baseline ---" -ForegroundColor Cyan

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

# 3. Detect Server Environment (Physical vs Virtual)
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$Bios = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue

Write-Host "`nPlatform Environment Detection:" -ForegroundColor Cyan
Write-Host "  Model:        $($ComputerSystem.Model)" -ForegroundColor White
Write-Host "  Manufacturer: $($Bios.Manufacturer)" -ForegroundColor White
Write-Host "  BIOS Version: $($Bios.SMBIOSBIOSVersion)" -ForegroundColor White

if ($ComputerSystem.Model -match "Virtual Machine|VMware|KVM|Hyper-V") {
    Write-Host "  [i] Virtual Domain Controller detected." -ForegroundColor Yellow
    Write-Host "      Ensure VM is Generation 2 (UEFI) with Secure Boot enabled and a virtual TPM (vTPM 2.0) attached." -ForegroundColor Gray
    Write-Host "      Hyper-V PowerShell: Set-VMFirmware -VMName '<DC>' -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows" -ForegroundColor Gray
    Write-Host "      Hyper-V PowerShell: Enable-VMTPM -VMName '<DC>'" -ForegroundColor Gray
} else {
    Write-Host "  [i] Physical Bare-Metal Server detected." -ForegroundColor Yellow
    Write-Host "      Ensure BIOS supervisor password is set, CSM is disabled, boot order is locked to RAID," -ForegroundColor Gray
    Write-Host "      VT-x/VT-d is enabled, and Out-of-Band BMC (iDRAC/iLO) has IPMI over LAN disabled." -ForegroundColor Gray
}

Write-Host "`n[+] Remediation script completed." -ForegroundColor Green
```

---

## Auditing & Verification

### PowerShell Audit Script

Run the following script to verify native UEFI boot mode, Secure Boot status, TPM 2.0 presence, and CPU virtualization extensions on Domain Controllers.

[Download Script: Audit-DcUefiSecurity.ps1](audit_scripts/Audit-DcUefiSecurity.ps1)

```powershell
# Audit-DcUefiSecurity.ps1
# Description: Audits local boot environment, Secure Boot, TPM, and virtualization properties on Domain Controllers.

Write-Host "--- Auditing UEFI Security Baseline on Domain Controller ---" -ForegroundColor Cyan

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

# 6. Retrieve Server & BIOS Firmware Specifications
$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$BiosDetails = Get-CimInstance -ClassName Win32_Bios -ErrorAction SilentlyContinue

Write-Host "  Platform Model:        $($ComputerSystem.Model)" -ForegroundColor White
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
Firmware and boot configuration telemetry on Domain Controllers is captured across Windows event channels:
* **Microsoft-Windows-Kernel-Boot**:
  * **Event ID 20**: Records boot mode type (Native UEFI vs PC-AT legacy BIOS).
  * **Event ID 32**: Records Secure Boot operational state during bootloader verification.
* **Microsoft-Windows-DeviceGuard/Operational**:
  * **Event ID 7000**: Virtualization-Based Security initialization and hardware requirements validation.
* **System Event Log**:
  * **Event ID 12 (Kernel-General)**: Operating system startup with system time and boot parameters.

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.8 (Virtualization-Based Security and Secure Boot Prerequisites)
* **ANSSI AD Hardening Guide**: Operational recommendations regarding hardware platform integrity and physical Tier 0 security.
* **DoD Windows Server STIG**: Rule `V-205710` (Enforce UEFI Secure Boot and Platform Firmware Lockdown)
* **Microsoft Security Guidelines**: Securing the Platform Hardware Root of Trust for Domain Controllers
