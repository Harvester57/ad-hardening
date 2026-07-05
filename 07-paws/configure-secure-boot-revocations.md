# [REQ-PAW-035] Configure Secure Boot Revocations and Bootloader Updates for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs).
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **BlackLotus Revocation Updates (CVE-2023-24932)**: `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`
    * `AvailableUpdates` = `>= 64` (REG_DWORD)

---

## Rationale
A vulnerability in the Windows Boot Manager allows an attacker with physical access or local administrative rights to bypass UEFI Secure Boot and execute unsigned code during the boot process (BlackLotus bootkit).

To fully mitigate this threat (CVE-2023-24932), Windows update revocations must be applied to the UEFI variables (DBX list) and code integrity SVN policies must be updated. This is managed via the `AvailableUpdates` registry key, which instructs the OS boot manager to write the revocation variables to firmware.

---

## Legacy Impact & Compatibility
* **BlackLotus Mitigation Risks**: Enforcing the BlackLotus DBX and SVN updates is a permanent, non-reversible action once written to the device firmware. If an administrator attempts to boot the machine using older, unpatched Windows installation media or recovery disks, the system will reject the boot manager and fail to boot. All recovery and deployment media must be updated with current security patches before applying these mitigations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To configure the update triggers for the DBX and Code Integrity boot manager revocations, define Registry GPO Preferences inside the PAW GPO:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the PAWs OU (e.g., `GPO_Hardening_PAWs`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create registry items to deploy the `AvailableUpdates` DWORD under `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`.
   * *Phase 1 (Apply DBX Update)*: Set `AvailableUpdates` = `64` (REG_DWORD)
   * *Phase 2 (Apply SVN and DB Updates)*: Set `AvailableUpdates` = `384` (REG_DWORD, sum of 256 and 128)
   * *Phase 3 (Enforce Code Integrity Boot Policy)*: Set `AvailableUpdates` = `512` (REG_DWORD)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the BlackLotus mitigation update trigger:

[Download Script: Set-PawSecureBootRevocations.ps1](implementation_scripts/Set-PawSecureBootRevocations.ps1)

```powershell
# Set-PawSecureBootRevocations.ps1
# Description: Triggers Secure Boot DBX and Code Integrity revocation updates for BlackLotus mitigation.

Write-Host "--- Configuring BlackLotus Secure Boot Mitigations ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Trigger DBX Update (Phase 1 DBX Update = 64)
Set-ItemProperty -Path $Path -Name "AvailableUpdates" -Value 64 -Type DWord -Force | Out-Null
Write-Host "[+] BlackLotus DBX revocation update configured in registry. A system reboot is required." -ForegroundColor Green
```

---

### Audit Script

Run the following script to check the status of Secure Boot revocations on the local machine:

[Download Script: Audit-PawSecureBootRevocations.ps1](audit_scripts/Audit-PawSecureBootRevocations.ps1)

```powershell
# Audit-PawSecureBootRevocations.ps1
# Description: Queries UEFI Secure Boot parameters and audits BlackLotus mitigation registry settings.

Write-Host "--- Auditing BlackLotus Mitigations ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# Audit AvailableUpdates registry key
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue
    $UpdateVal = if ($Val) { $Val.AvailableUpdates } else { 0 }
    
    # Check if at least DBX update (64) is enabled
    if ($UpdateVal -ge 64) {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Non-Compliant - DBX/SVN revocations not triggered)" -ForegroundColor Red
        $script:NonCompliant = $true
    }
} else {
    Write-Host "    - BlackLotus Revocation Updates: Registry path not found (Non-Compliant)" -ForegroundColor Red
    $script:NonCompliant = $true
}

if ($script:NonCompliant) {
    exit 1
}
```

---

## Sources & Compliance References
* **Microsoft Security Baseline Focus**: Windows Administrative Templates (Secure Boot Revocation Updates)
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
