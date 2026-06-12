# Hardening Requirement: Enable Hardware Virtualization and DMA Protection

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\System\Kernel DMA Protection
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection

---

## Rationale
Virtualization-Based Security (VBS) and Windows Defender Credential Guard isolate sensitive security processes (like LSA) inside a hardware-virtualized container to prevent memory dumping and credential harvesting. However, these OS-level security boundaries are entirely reliant on hardware-level protections.

Enabling hardware virtualization and DMA protection guarantees:
1. **Isolated Execution Environment**: Enforcing CPU Virtualization Extensions (Intel VT-x or AMD-V) in the UEFI allows the hypervisor to isolate the VBS secure kernel from the host Windows operating system.
2. **Physical DMA Protection**: Enforcing IOMMU (Intel VT-d or AMD-Vi) at the firmware level enables Kernel DMA Protection. This blocks malicious peripherals (e.g., PCIe cards or Thunderbolt devices) from executing unauthorized Direct Memory Access (DMA) attacks to read or write to host system memory, preventing attackers from extracting BitLocker keys or credential secrets directly from RAM.
3. **Hardware Root of Trust**: Activating the Trusted Platform Module (TPM) 2.0 enables cryptographic boot measurement logging (PCR banks). TPM 2.0 ensures that the system boot configuration has not been modified prior to unsealing the BitLocker volume decryption keys.

---

## Legacy Impact & Compatibility
* **Hardware Baseline**: Systems must support CPU virtualization, Second Level Address Translation (SLAT), and input-output memory management (IOMMU). Unsupported hardware will prevent VBS and Credential Guard from initiating.
* **Peripheral Compatibility**: Older or non-certified Thunderbolt/PCIe devices that do not support DMA-remapping (DMA routing checks) may be blocked from functioning when Kernel DMA Protection is active. This is acceptable for a PAW, where external hardware connections must be strictly restricted.
* **Nested Virtualization**: Enabling hardware virtualization for VBS may conflict with older third-party hypervisors (such as legacy versions of VirtualBox or VMware Workstation) that do not support nesting under Microsoft Hyper-V.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To enforce Kernel DMA Protection across the PAW infrastructure, implement the following GPO settings:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
4. Configure the following setting:
   * **Policy**: `Enable Kernel DMA Protection`
   * **Setting**: `Enabled`
5. Link the GPO to the appropriate OU containing target PAWs.

*Note: Enforce hardware-level CPU Virtualization (VT-x/AMD-V), IOMMU (VT-d/AMD-Vi), and TPM 2.0 manually in the UEFI menu of each device.*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure local registry keys to enforce Kernel DMA Protection and programmatically audit the hardware security baseline.

#### 1. Local Remediation (Enforce Kernel DMA Protection)

Run the following script to enforce the DMA Protection policy locally:

[Download Script: Configure-KernelDMAProtection.ps1](implementation_scripts/Configure-KernelDMAProtection.ps1)

```powershell
# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 0 (Block all DMA until user logs on)
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 0 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied." -ForegroundColor Green
```

#### 2. Local Audit (TPM, Virtualization, and DMA Support)

Run the following script to audit the status of the required hardware security components:

[Download Script: Audit-HardwareSecurityFeatures.ps1](audit_scripts/Audit-HardwareSecurityFeatures.ps1)

```powershell
# Audit-HardwareSecurityFeatures.ps1
# Description: Audits TPM 2.0, CPU Virtualization, and IOMMU/DMA status.

Write-Host "--- Auditing Hardware Security Features ---" -ForegroundColor Cyan

# 1. Audit TPM 2.0 Status
$Tpm = Get-Tpm -ErrorAction SilentlyContinue
if ($Tpm) {
    if ($Tpm.TpmPresent -eq $true) {
        $TpmColor = "Red"
        if ($Tpm.TpmReady -eq $true) {
            $TpmColor = "Green"
        }
        Write-Host "Status: TPM Present: $($Tpm.TpmPresent) | Ready: $($Tpm.TpmReady)" -ForegroundColor $TpmColor
    } else {
        Write-Host "VULNERABLE: TPM 2.0 is not detected on this system." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: TPM verification cmdlet failed." -ForegroundColor Red
}

# 2. Audit VBS and DMA Status via Win32_DeviceGuard
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # VirtualizationBasedSecurityStatus: 2 = Running
    $VbsStatus = $DG.VirtualizationBasedSecurityStatus
    $VbsColor = "Red"
    if ($VbsStatus -eq 2) {
        $VbsColor = "Green"
    }
    Write-Host "Status: Virtualization-Based Security Status: $($VbsStatus) (Required = 2 [Running])" -ForegroundColor $VbsColor
    
    # AvailableSecurityProperties: 3 = DMA Protection (IOMMU)
    $DmaSupported = $DG.AvailableSecurityProperties -contains 3
    $DmaColor = "Red"
    if ($DmaSupported -eq $true) {
        $DmaColor = "Green"
    }
    Write-Host "Status: Hardware IOMMU/DMA Protection: $($DmaSupported)" -ForegroundColor $DmaColor
    
    # RequiredSecurityProperties: 3 = DMA Protection enforced
    $DmaEnforced = $DG.RequiredSecurityProperties -contains 3
    $EnforcedColor = "Red"
    if ($DmaEnforced -eq $true) {
        $EnforcedColor = "Green"
    }
    Write-Host "Status: DMA Protection Policy Enforced: $($DmaEnforced)" -ForegroundColor $EnforcedColor
    
} catch {
    Write-Host "VULNERABLE: Win32_DeviceGuard WMI class could not be queried. VBS is likely inactive." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R58 (Use of Privileged Access Workstations)
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.19.1 (Configure Enable Kernel DMA Protection), Section 18.8.14.1 (Turn On Virtualization Based Security)
* **Microsoft Security Guidelines**: Kernel DMA Protection reference architecture
