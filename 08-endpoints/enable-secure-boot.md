# Hardening Requirement: Enable Secure Boot

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware configuration (Hardware/BIOS level)
  * Computer Configuration\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security

---

## Rationale
Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM). 

When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.

If Secure Boot is disabled:
1. **Bootkits & Rootkits**: Attackers with physical access or local administrator privileges can replace the system bootloader with a malicious bootloader (bootkit). This bootkit executes before the Windows operating system loads, allowing it to bypass all Windows security controls, disable antivirus software, and run completely undetected.
2. **Virtualization-Based Security**: Advanced Windows defenses (like Credential Guard and Device Guard) depend on hardware-rooted trust. If Secure Boot is disabled, Virtualization-Based Security (VBS) cannot verify platform integrity, rendering these protections ineffective.

---

## Legacy Impact & Compatibility
* **BIOS Mode Conversion**: Systems running in legacy BIOS mode (Compatibility Support Module - CSM) instead of Native UEFI cannot use Secure Boot. Converting these systems requires changing partition styles from MBR to GPT (using tools like `MBR2GPT.exe`) and changing firmware settings, which can cause boot failures if not executed correctly.
* **Dual-Boot Systems**: If the workstation dual-boots with unsigned Linux distributions or runs legacy recovery media, the firmware will reject the bootloader, preventing boot.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

UEFI Secure Boot must be enabled in the hardware firmware menu directly (BIOS settings). However, you can enforce policies to audit and lock VBS to require Secure Boot:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security`
   * **Setting**: `Enabled`
   * **Select Platform Security Level**: Select `Secure Boot` or `Secure Boot and DMA Protection` in the dropdown menu.

*Note: Enforcing this policy ensures Windows will refuse to enable Virtualization-Based Security unless the local firmware has UEFI Secure Boot successfully active.*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Since Secure Boot is a hardware firmware configuration, it cannot be turned on from within Windows using registry settings. However, you can programmatically audit the state of Secure Boot to flag non-compliant hardware.

Run the following script to check the status of Secure Boot on the local machine:

```powershell
# Audit-SecureBoot.ps1
# Queries UEFI Secure Boot parameters using native cmdlets.

Write-Host "--- Auditing UEFI Secure Boot ---" -ForegroundColor Cyan

try {
    # Confirm-SecureBootUEFI returns $true if Secure Boot is active, $false if disabled,
    # and throws an exception if the platform does not support UEFI or Secure Boot.
    $SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop
    
    $Color = if ($SecureBootState -eq $true) { "Green" } else { "Red" }
    Write-Host "    - Secure Boot Active: $SecureBootState" -ForegroundColor $Color
} catch [System.PlatformNotSupportedException] {
    Write-Host "    - VULNERABLE: UEFI Secure Boot is not supported on this platform (Legacy BIOS mode)." -ForegroundColor Red
} catch {
    # If cmdlet throws unauthorized access or not enabled error
    Write-Host "    - VULNERABLE: Secure Boot is disabled in firmware or cannot be verified. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

*To verify platform boot style (UEFI vs Legacy BIOS):*
```powershell
# Check boot type environment variable
$BootType = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name "PEFirmwareType" -ErrorAction SilentlyContinue
if ($BootType) {
    # PEFirmwareType: 1 = BIOS, 2 = UEFI
    $TypeVal = $BootType.PEFirmwareType
    $BootColor = if ($TypeVal -eq 2) { "Green" } else { "Red" }
    $TypeName = if ($TypeVal -eq 2) { "UEFI" } else { "Legacy BIOS" }
    Write-Host "    - Boot Environment Type: $TypeName ($TypeVal)" -ForegroundColor $BootColor
} else {
    Write-Host "    - Boot Environment Type could not be read from registry." -ForegroundColor Yellow
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.8.14.1 (Configure Turn On Virtualization Based Security: Select Platform Security Level)
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
