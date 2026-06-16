# [REQ-PAW-030] Enable Secure Boot

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs).
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * UEFI Firmware configuration (Hardware/BIOS level)
  * Computer Configuration\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security
  * **BlackLotus Revocation Updates (CVE-2023-24932)**: `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot` -> `AvailableUpdates` (REG_DWORD = 64 | 256 | 128 | 512 dependent on mitigation phase)

---

## Rationale
Secure Boot is a security standard developed by members of the PC industry to help ensure that a device boots using only software that is trusted by the Original Equipment Manufacturer (OEM).

When the PC starts, the firmware checks the signature of each piece of boot software, including UEFI firmware drivers (also known as Option ROMs), EFI applications, and the operating system. If the signatures are valid, the PC boots, and the firmware gives control to the operating system.

If Secure Boot is disabled:
1. **Bootkits & Rootkits**: Attackers with physical access or local administrator privileges can replace the system bootloader with a malicious bootloader (bootkit). This bootkit executes before the Windows operating system loads, allowing it to bypass all Windows security controls, disable antivirus software, and run completely undetected.
2. **Virtualization-Based Security**: Advanced Windows defenses (like Credential Guard and Device Guard) depend on hardware-rooted trust. If Secure Boot is disabled, Virtualization-Based Security (VBS) cannot verify platform integrity, rendering these protections ineffective.
3. **BlackLotus Bootkit Bypass Mitigations (CVE-2023-24932)**: A vulnerability in the Windows Boot Manager allows an attacker with physical access or local administrative rights to bypass Secure Boot and execute unsigned code during the boot process (BlackLotus bootkit). To fully mitigate this threat, Windows update revocations must be applied to the UEFI variables (DBX list) and code integrity SVN policies must be updated. This is managed via the `AvailableUpdates` registry key, which instructs the OS boot manager to write the revocation variables to firmware.

---

## Legacy Impact & Compatibility
* **BIOS Mode Conversion**: Systems running in legacy BIOS mode (Compatibility Support Module - CSM) instead of Native UEFI cannot use Secure Boot. Converting these systems requires changing partition styles from MBR to GPT (using tools like `MBR2GPT.exe`) and changing firmware settings; refer to [REQ-PAW-011 - UEFI Firmware Security Hardening](configure-uefi-security.md) for firmware settings. Improper conversion can cause boot failures if not executed correctly.
* **Dual-Boot Systems**: If the workstation dual-boots with unsigned Linux distributions or runs legacy recovery media, the firmware will reject the bootloader, preventing boot.
* **BlackLotus Mitigation Risks**: Enforcing the BlackLotus DBX and SVN updates is a permanent, non-reversible action once written to the device firmware. If an administrator attempts to boot the machine using older, unpatched Windows installation media or recovery disks, the system will reject the boot manager and fail to boot. All recovery and deployment media must be updated with current security patches before applying these mitigations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

UEFI Secure Boot must be enabled in the hardware firmware menu directly (BIOS settings). However, you can enforce policies to audit and lock VBS to require Secure Boot:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the PAWs OU (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security`
   * **Setting**: `Enabled`
     * **Select Platform Security Level**: Select `Secure Boot` or `Secure Boot and DMA Protection` in the dropdown menu.

#### Deploy BlackLotus Revocation Registry Keys via GPO Preferences
To configure the update triggers for the DBX and Code Integrity boot manager revocations, define Registry GPO Preferences inside the PAW GPO:
1. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
2. Create registry items to deploy the `AvailableUpdates` DWORD under `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`.
   * *Phase 1 (Apply DBX Update)*: Set `AvailableUpdates` = 64 (REG_DWORD)
   * *Phase 2 (Apply SVN and DB Updates)*: Set `AvailableUpdates` = 384 (REG_DWORD, sum of 256 and 128)
   * *Phase 3 (Enforce Code Integrity Boot Policy)*: Set `AvailableUpdates` = 512 (REG_DWORD)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Since Secure Boot is a hardware firmware configuration, it cannot be turned on from within Windows using registry settings. However, you can programmatically audit the state of Secure Boot to flag non-compliant hardware.

Run the following script to check the status of Secure Boot on the local machine:

[Download Script: Audit-PawSecureBoot.ps1](audit_scripts/Audit-PawSecureBoot.ps1)

```powershell
# Audit-PawSecureBoot.ps1
# Queries UEFI Secure Boot parameters and audits BlackLotus mitigation registry settings.

Write-Host "--- Auditing UEFI Secure Boot & BlackLotus Mitigations ---" -ForegroundColor Cyan

$script:NonCompliant = $false

try {
    $SecureBootState = Confirm-SecureBootUEFI -ErrorAction Stop
    
    $Color = if ($SecureBootState -eq $true) { "Green" } else { "Red" }
    Write-Host "    - Secure Boot Active: $SecureBootState" -ForegroundColor $Color
    if ($SecureBootState -eq $false) { $script:NonCompliant = $true }
} catch [System.PlatformNotSupportedException] {
    Write-Host "    - UEFI Secure Boot is not supported on this platform (Legacy BIOS mode)." -ForegroundColor Red
    $script:NonCompliant = $true
} catch {
    Write-Host "    - Secure Boot is disabled in firmware or cannot be verified. Error: $($_.Exception.Message)" -ForegroundColor Red
    $script:NonCompliant = $true
}

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue
    $UpdateVal = if ($Val) { $Val.AvailableUpdates } else { 0 }
    
    if ($UpdateVal -ge 64) {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal" -ForegroundColor Green
    } else {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Non-Compliant - DBX/SVN revocations not triggered)" -ForegroundColor Red
        $script:NonCompliant = $true
    }
} else {
    Write-Host "    - BlackLotus Revocation Updates: Registry path not found" -ForegroundColor Red
    $script:NonCompliant = $true
}

if ($script:NonCompliant) {
    exit 1
}
```

To verify platform boot style (UEFI vs Legacy BIOS):
```powershell
$BootType = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control" -Name "PEFirmwareType" -ErrorAction SilentlyContinue
if ($BootType) {
    $TypeVal = $BootType.PEFirmwareType
    $BootColor = if ($TypeVal -eq 2) { "Green" } else { "Red" }
    $TypeName = if ($TypeVal -eq 2) { "UEFI" } else { "Legacy BIOS" }
    Write-Host "    - Boot Environment Type: $TypeName ($TypeVal)" -ForegroundColor $BootColor
} else {
    Write-Host "    - Boot Environment Type could not be read from registry." -ForegroundColor Yellow
}
```

---

### Remediation Script

[Download Script: Set-PawSecureBoot.ps1](implementation_scripts/Set-PawSecureBoot.ps1)

```powershell
# Set-PawSecureBoot.ps1
# Description: Triggers Secure Boot DBX and Code Integrity revocation updates for BlackLotus mitigation.

Write-Host "--- Configuring BlackLotus Secure Boot Mitigations ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

Set-ItemProperty -Path $Path -Name "AvailableUpdates" -Value 64 -Type DWord -Force | Out-Null
Write-Host "BlackLotus DBX revocation update configured in registry. A system reboot is required." -ForegroundColor Green
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.8.14.1 (Configure Turn On Virtualization Based Security: Select Platform Security Level)
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
