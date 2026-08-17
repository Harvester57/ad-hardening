# [REQ-END-014] Enable Hardware Virtualization and DMA Protection

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (version 1803 and above) Enterprise/Professional, Windows 11 Enterprise/Professional, Windows Server 2019 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Kernel DMA Protection
  * **Policy**: `Enumeration policy for external devices incompatible with Kernel DMA Protection`
  * **Registry Location**: HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection
    * `DeviceEnumerationPolicy` = `0` (REG_DWORD, Block All)

---

## Rationale
Direct Memory Access (DMA) allows hardware devices to read and write directly to physical system memory (RAM) over high-speed buses without CPU or operating system arbitration. External expansion ports—such as Thunderbolt 3, Thunderbolt 4, USB4, and hot-plug PCIe slots—expose internal PCI Express lanes directly to external peripherals.

If external DMA interfaces are left unprotected, an attacker with physical access to an unattended, locked, or stolen endpoint can connect malicious hardware tools or implants (such as PCILeech or USB3380 DMA attack adapters) to perform drive-by physical DMA attacks. Through unrestricted DMA access, attackers can extract sensitive secrets directly from RAM—including BitLocker full-volume encryption keys, DPAPI master keys, LSASS authentication tokens, Kerberos tickets, and cached credentials—or write to memory to inject kernel payloads and bypass Windows lock screens.

Configuring Kernel DMA Protection and enforcing strict external device enumeration mitigates this threat vector:
1. **IOMMU Memory Isolation**: Kernel DMA Protection utilizes the system's Input-Output Memory Management Unit (IOMMU: Intel VT-d or AMD-Vi) and ACPI DMAR tables to create hypervisor-enforced memory sandboxes for peripheral devices. For DMA-remapping-compatible devices, the operating system isolates device DMA transfers exclusively to the specific memory buffers allocated to that device's driver, blocking unauthorized access to adjacent physical RAM.
2. **Mitigating Incompatible External Devices**: External devices and drivers are classified into two categories: those that support DMA remapping and those that do not. If an incompatible or rogue peripheral without DMA-remapping support is connected, Windows default behavior may permit enumeration or delay it until user login. Setting the enumeration policy to **Block All** (`DeviceEnumerationPolicy = 0`) guarantees that any external device whose drivers do not explicitly support DMA remapping is unconditionally blocked from initializing, loading drivers, or executing DMA transfers.
3. **Closing the Physical Hot-Plug Attack Surface**: By blocking incompatible external DMA devices, the operating system ensures that only verified, DMA-remapping-compliant peripherals operate under strict hypervisor IOMMU containment, preventing drive-by memory dumping attacks while preserving device functionality for certified hardware.

---

## Legacy Impact & Compatibility
* **Incompatible External Peripherals**: External devices connected via Thunderbolt, USB4, or PCIe expansion slots that lack DMA-remapping-compatible drivers (such as legacy Thunderbolt 1 and 2 docks, older external PCIe enclosures, non-certified external GPUs, or legacy video capture cards) will be blocked from functioning. Only peripherals with modern, DMA-remapping-certified drivers will enumerate and operate.
* **Standard USB Devices**: Standard USB peripherals (such as USB 2.0/3.0/3.1 flash drives, keyboards, mice, and standard USB-C accessories that do not tunnel PCIe / DMA traffic) are managed by standard USB host controllers and are completely unaffected by this policy.
* **Hardware and Firmware Pre-requisites**: Kernel DMA Protection requires platform hardware support (IOMMU / Intel VT-d or AMD-Vi enabled in UEFI firmware, ACPI Kernel DMA Protection / DMAR table support). On systems without platform Kernel DMA Protection support in firmware, this policy enforces the blocking of incompatible external devices when DMA is attempted.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To enforce the Kernel DMA Protection external device enumeration policy across standard client workstations and member servers, implement the following GPO settings:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the target workstations and member servers OUs (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
4. Configure the following setting:
   * **Policy**: `Enumeration policy for external devices incompatible with Kernel DMA Protection`
   * **Setting**: `Enabled`
   * **Enumeration policy**: Select **Block All** (value `0`)
5. Link the GPO to the appropriate OUs.

*Note: For Kernel DMA Protection to operate with maximum security, ensure platform hardware virtualization and IOMMU extensions (Intel VT-d or AMD-Vi) are enabled in the UEFI configuration menu as outlined in [REQ-END-013 - UEFI Firmware Security Hardening](configure-uefi-security.md).*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure local registry keys to enforce Kernel DMA Protection and programmatically audit the hardware security baseline.

#### 1. Local Remediation (Enforce Kernel DMA Protection)

Run the following script to configure the Kernel DMA Protection policy locally:

[Download Script: Configure-KernelDMAProtection.ps1](implementation_scripts/Configure-KernelDMAProtection.ps1)

```powershell
# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection and block incompatible external DMA devices.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path -Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 0 (Block all external DMA devices incompatible with Kernel DMA Protection)
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied (DeviceEnumerationPolicy = 0 [Block All])." -ForegroundColor Green
```

#### 2. Local Audit (Kernel DMA Protection, IOMMU, and Hardware Baseline)

Run the following script to audit the status of Kernel DMA Protection, IOMMU support, and the required hardware security components:

[Download Script: Audit-HardwareSecurityFeatures.ps1](audit_scripts/Audit-HardwareSecurityFeatures.ps1)

```powershell
# Audit-HardwareSecurityFeatures.ps1
# Description: Audits Kernel DMA Protection registry policy, hardware IOMMU/DMA status, VBS state, and TPM readiness.

Write-Host "--- Auditing Kernel DMA Protection and Hardware Security Baseline ---" -ForegroundColor Cyan

# 1. Audit Kernel DMA Protection Registry Policy
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
$EnumPolicy = Get-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -ErrorAction SilentlyContinue

if ($null -ne $EnumPolicy -and $EnumPolicy.DeviceEnumerationPolicy -eq 0) {
    Write-Host "Status: Kernel DMA Protection Policy (DeviceEnumerationPolicy): 0 (Block All) [COMPLIANT]" -ForegroundColor Green
} else {
    $CurrentVal = if ($null -ne $EnumPolicy) { $EnumPolicy.DeviceEnumerationPolicy } else { "Not Configured" }
    Write-Host "VULNERABLE: Kernel DMA Protection Policy is '$($CurrentVal)'. Expected: 0 (Block All)." -ForegroundColor Red
}

# 2. Audit VBS and Hardware DMA/IOMMU Status via Win32_DeviceGuard
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # VirtualizationBasedSecurityStatus: 2 = Running
    $VbsStatus = $DG.VirtualizationBasedSecurityStatus
    if ($VbsStatus -eq 2) {
        Write-Host "Status: Virtualization-Based Security (VBS) Status: 2 (Running) [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Virtualization-Based Security (VBS) is not running (Status: $($VbsStatus))." -ForegroundColor Red
    }
    
    # AvailableSecurityProperties: 3 = DMA Protection (IOMMU)
    $DmaSupported = $DG.AvailableSecurityProperties -contains 3
    if ($DmaSupported -eq $true) {
        Write-Host "Status: Hardware IOMMU / DMA Remapping Support: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Hardware IOMMU / DMA Protection is not available on this platform." -ForegroundColor Red
    }
    
    # RequiredSecurityProperties: 3 = DMA Protection enforced
    $DmaEnforced = $DG.RequiredSecurityProperties -contains 3
    if ($DmaEnforced -eq $true) {
        Write-Host "Status: DMA Protection Security Policy Enforced: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "Status: DMA Protection Security Policy Enforced: False [INFO]" -ForegroundColor Yellow
    }
} catch {
    Write-Host "VULNERABLE: Win32_DeviceGuard WMI class could not be queried. VBS / Device Guard is inactive." -ForegroundColor Red
}

# 3. Audit TPM 2.0 Status
$Tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($null -ne $Tpm) {
    if ($Tpm.TpmPresent -eq $true -and $Tpm.TpmReady -eq $true) {
        Write-Host "Status: TPM 2.0 Present: True | Ready: True [COMPLIANT]" -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: TPM Present: $($Tpm.TpmPresent) | Ready: $($Tpm.TpmReady) (Expected: Present and Ready)." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: TPM verification cmdlet failed." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.8.19.1 (Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All')
* **CIS Microsoft Windows 11 Benchmark**: Section 18.8.19.1 (Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All')
* **Microsoft Security Guidelines**: Kernel DMA Protection (Memory Access Protection) reference architecture
* **ANSSI AD Hardening Guide**: Recommendations on hardware platform integrity and physical interface security
