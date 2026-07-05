# [REQ-END-009] Enable UEFI Secure Boot

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware configuration (Hardware/BIOS level)
  * HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    * `UEFISecureBootEnabled` = `1` (REG_DWORD)

---

## Rationale
Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM).

When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.

If Secure Boot is disabled:
1. **Bootkits & Rootkits**: Attackers with physical access or local administrator privileges can replace the system bootloader with a malicious bootloader (bootkit). This bootkit executes before the Windows operating system loads, allowing it to bypass all Windows security controls, disable antivirus software, and run completely undetected.
2. **Virtualization-Based Security**: Advanced Windows defenses (like Credential Guard and Device Guard) depend on hardware-rooted trust. If Secure Boot is disabled, Virtualization-Based Security (VBS) cannot verify platform integrity, rendering these protections ineffective.

---

## Legacy Impact & Compatibility
* **BIOS Mode Conversion**: Systems running in legacy BIOS mode (Compatibility Support Module - CSM) instead of Native UEFI cannot use Secure Boot. Converting these systems requires changing partition styles from MBR to GPT (using tools like `MBR2GPT.exe`) and changing firmware settings; refer to [REQ-END-013 - UEFI Firmware Security Hardening](configure-uefi-security.md) for firmware settings. Improper conversion can cause boot failures if not executed correctly.
* **Dual-Boot Systems**: If the workstation dual-boots with unsigned Linux distributions or runs legacy recovery media, the firmware will reject the bootloader, preventing boot.

---

## Implementation Steps

### Option A: Manual UEFI Firmware Configuration (Preferred)

UEFI Secure Boot must be enabled in the hardware firmware menu directly (BIOS settings) during system startup:

1. Turn on or restart the workstation and access the UEFI utility screen by pressing the vendor-specific key during POST (typically Delete, F2, F10, or F12).
2. Navigate to the **Security** or **Secure Boot** section:
   * Ensure **Secure Boot** is set to **Enabled**.
   * Ensure the **Secure Boot Mode** is set to **Deployed** or **User Mode** (not Setup Mode).
3. Save the configuration and restart the workstation.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Since Secure Boot is a hardware firmware configuration, it cannot be turned on from within Windows using registry settings. However, you can programmatically audit the state of Secure Boot to flag non-compliant hardware.

Run the following script to check the status of Secure Boot on the local machine:

[Download Script: Audit-SecureBoot.ps1](audit_scripts/Audit-SecureBoot.ps1)

```powershell
# Audit-SecureBoot.ps1
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8 (VBS Prerequisites)
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
