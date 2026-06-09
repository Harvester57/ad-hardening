# Hardening Requirement: Enable Hardware Virtualization and DMA Protection

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\System\Kernel DMA Protection
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection

---

## Rationale
Operating-system-level security layers such as Virtualization-Based Security (VBS) and Windows Defender Credential Guard are designed to isolate credentials and kernel code integrity in a virtual secure environment. However, these layers rely entirely on the security of the underlying hardware platform and motherboard architecture.

Enabling hardware virtualization and DMA protection ensures:
1. **Hypervisor Memory Isolation**: Activating CPU Virtualization Extensions (Intel VT-x or AMD-V) in the UEFI allows the Windows hypervisor to separate the host operating system from the secure kernel.
2. **Direct Memory Access (DMA) Protection**: Enforcing IOMMU (Intel VT-d or AMD-Vi) at the firmware level enables Kernel DMA Protection. This blocks malicious peripherals connected to hot-plug ports (such as Thunderbolt, USB4, or PCIe expansion slots) from executing unauthorized DMA requests to read or modify physical RAM, mitigating physical attacks to extract BitLocker encryption keys or in-memory credential tokens.
3. **Hardware Trust Anchoring**: Enabling TPM 2.0 provides the physical root of trust needed to verify boot integrity (via PCR measurements) and safely store cryptographic keys, preventing the operating system from booting or unsealing disk encryption if the hardware state has been tampered with.

---

## Legacy Impact & Compatibility
* **Hardware Requirements**: Systems must support CPU virtualization, Second Level Address Translation (SLAT), and input-output memory management (IOMMU). Modern hardware supports these features by default, but older server models or legacy clients may need upgrades.
* **External Device Blocking**: Enforcing Kernel DMA Protection may prevent non-compliant hot-plug peripherals (such as legacy Thunderbolt docking stations or older external GPUs) from running if they do not support DMA remapping. To balance usability on standard endpoints, policies can be configured to allow external devices only after a user logs on and unlocks the session.
* **Third-Party Virtualization**: Activating hardware virtualization for VBS may cause conflicts with older third-party virtualization software that does not support nested execution under Microsoft Hyper-V.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To enforce Kernel DMA Protection across standard client workstations and member servers, implement the following GPO settings:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the target workstations and servers OUs (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Kernel DMA Protection`
4. Configure the following setting:
   * **Policy**: `Enable Kernel DMA Protection`
   * **Setting**: `Enabled`
5. Link the GPO to the appropriate OUs.

*Note: In addition to the GPO policy, ensure CPU Virtualization (VT-x/AMD-V), IOMMU (VT-d/AMD-Vi), and TPM 2.0 are manually enabled in the UEFI configuration menu of the systems.*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure local registry keys to enforce Kernel DMA Protection and programmatically audit the hardware security baseline.

#### 1. Local Remediation (Enforce Kernel DMA Protection)

Run the following script to configure the Kernel DMA Protection policy locally:

```powershell
# Configure-KernelDMAProtection.ps1
# Description: Configures registry keys to enable Kernel DMA Protection.

Write-Host "--- Enforcing Kernel DMA Protection ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\KernelDMAProtection"
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# DeviceEnumerationPolicy = 1 (Block all external DMA devices until a user logs on)
# Note: For maximum security, set to 0 (Block all). Value 1 is standard for standard endpoints.
Set-ItemProperty -Path $RegPath -Name "DeviceEnumerationPolicy" -Value 1 -Type DWord
Write-Host "Status: Kernel DMA Protection registry configuration applied." -ForegroundColor Green
```

#### 2. Local Audit (TPM, Virtualization, and DMA Support)

Run the following script to audit the status of the required hardware security components:

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
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.19.1 (Configure Enable Kernel DMA Protection), Section 18.8.14.1 (Turn On Virtualization Based Security)
* **Microsoft Security Guidelines**: Kernel DMA Protection reference architecture
