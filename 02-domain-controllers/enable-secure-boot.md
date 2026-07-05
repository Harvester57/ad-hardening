# [REQ-DC-032] Enable UEFI Secure Boot

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware configuration (Hardware/BIOS level or Hypervisor/VM level)
  * HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    * `UEFISecureBootEnabled` = `1` (REG_DWORD)

---

## Rationale
Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM).

When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.

For Tier 0 assets like Domain Controllers, firmware integrity is critical. If Secure Boot is disabled:
1. **Bootkits & Rootkits**: Attackers with physical access or hosting infrastructure control (in virtual environments) can replace the boot manager with a malicious bootloader (bootkit) to bypass LSASS protections and all OS security controls before the Windows kernel loads.
2. **Virtualization-Based Security**: Advanced security boundaries (like LSA Protection and Device Guard) depend on hardware-rooted trust. Without UEFI Secure Boot active, virtualization-based security capabilities cannot execute with proper system measurements.

---

## Legacy Impact & Compatibility
* **Virtual Domain Controllers**: When running Domain Controllers as virtual machines, UEFI and Secure Boot must be enabled in the hypervisor settings (e.g., Gen 2 VMs in Hyper-V with Secure Boot enabled, or EFI boot with Secure Boot enabled in VMware vSphere).
* **BIOS Mode Conversion**: Physical Domain Controllers running in legacy BIOS mode (CSM) instead of Native UEFI cannot use Secure Boot. Converting these systems requires partition style migration (MBR to GPT) and BIOS changes; refer to [REQ-DC-018 - Harden Virtualization Hosts for Domain Controllers](harden-dc-virtualization-hosts.md) for virtualization host hardening requirements.

---

## Implementation Steps

### Option A: Firmware / Hypervisor Configuration (Preferred)

UEFI Secure Boot must be configured at the hardware or hypervisor layer:

* **Physical Servers**: Access the UEFI firmware configuration utility during POST (Delete, F2, F10, or F12) and enable **Secure Boot** in the Security settings.
* **Hyper-V Gen 2 Virtual Machines**:
  1. Open **Hyper-V Manager**.
  2. Select the Domain Controller VM and open its **Settings**.
  3. Navigate to **Security** -> check **Enable Secure Boot** -> select **Microsoft Windows** template.
* **VMware vSphere Virtual Machines**:
  1. Open the **vSphere Client**.
  2. Edit settings of the Domain Controller VM -> go to **VM Options** -> **Boot Options**.
  3. Set Firmware to **EFI** and check **Enable UEFI Secure Boot**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Secure Boot cannot be configured from within the OS using registry settings. However, you must programmatically audit the state of Secure Boot to flag non-compliant hardware.

Run the following script to check the status of Secure Boot on the Domain Controller:

[Download Script: Audit-DcSecureBoot.ps1](audit_scripts/Audit-DcSecureBoot.ps1)

```powershell
# Audit-DcSecureBoot.ps1
# Description: Queries UEFI Secure Boot parameters and audits UEFI Secure Boot status.

Write-Host "--- Auditing UEFI Secure Boot ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# 1. Verify boot environment type
if ($env:firmware_type -eq "UEFI") {
    Write-Host "    - Boot Environment Type: UEFI" -ForegroundColor Green
} else {
    Write-Host "    - VULNERABLE: System booted in Legacy BIOS mode (CSM enabled) or firmware type is unrecognized." -ForegroundColor Red
    $script:NonCompliant = $true
}

# 2. Verify Secure Boot status
try {
    # Confirm-SecureBootUEFI returns $true if Secure Boot is active, $false if disabled,
    # and throws an exception if the platform does not support UEFI or Secure Boot.
    $SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop
    
    $Color = if ($SecureBootState -eq $true) { "Green" } else { "Red" }
    Write-Host "    - Secure Boot Active: $SecureBootState" -ForegroundColor $Color
    if ($SecureBootState -eq $false) { $script:NonCompliant = $true }
} catch [System.PlatformNotSupportedException] {
    Write-Host "    - VULNERABLE: UEFI Secure Boot is not supported on this platform (Legacy BIOS mode)." -ForegroundColor Red
    $script:NonCompliant = $true
} catch {
    # If cmdlet throws unauthorized access or not enabled error
    Write-Host "    - VULNERABLE: Secure Boot is disabled in firmware or cannot be verified. Error: $($_.Exception.Message)" -ForegroundColor Red
    $script:NonCompliant = $true
}

if ($script:NonCompliant) {
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.8 (Virtualization Based Security Prerequisites)
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
