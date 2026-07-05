# [REQ-END-035] Configure Secure Boot Revocations and Bootloader Updates

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **BlackLotus Revocation Updates (CVE-2023-24932)**: `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`
    * `AvailableUpdates` = `>= 0x4000` (REG_DWORD)

---

## Rationale
A vulnerability in the Windows Boot Manager allows an attacker with physical access or local administrative rights to bypass UEFI Secure Boot and execute unsigned code during the boot process (BlackLotus bootkit). 

To fully mitigate this threat (CVE-2023-24932), Windows update revocations must be applied to the UEFI variables (DBX list) and code integrity SVN policies must be updated. This is managed via the `AvailableUpdates` registry key, which instructs the OS boot manager to write the revocation variables to firmware.

According to the latest Microsoft guidelines, the recommended trigger value for enterprise deployments to apply all security updates (including the new Windows UEFI CA 2023 certificates and boot manager updates) is **`0x5944`** (hex) / **`22852`** (decimal). As the OS processes this bitmask, the value is cleared incrementally, ending up at **`0x4000`** (hex) / **`16384`** (decimal) upon successful completion.

---

## Legacy Impact & Compatibility
* **BlackLotus Mitigation Risks**: Enforcing the BlackLotus DBX and SVN updates is a permanent, non-reversible action once written to the device firmware. If an administrator attempts to boot the machine using older, unpatched Windows installation media or recovery disks, the system will reject the boot manager and fail to boot. All recovery and deployment media must be updated with current security patches before applying these mitigations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To configure the update triggers for the DBX and Code Integrity boot manager revocations, define Registry GPO Preferences inside the endpoints GPO:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a registry item to deploy the `AvailableUpdates` DWORD under `HKLM\SYSTEM\CurrentControlSet\Control\Secureboot`.
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Secureboot`
   * **Value Name**: `AvailableUpdates`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `22852` (Decimal) or `5944` (Hex)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the BlackLotus mitigation update trigger:

[Download Script: Set-SecureBootRevocations.ps1](implementation_scripts/Set-SecureBootRevocations.ps1)

```powershell
# Set-SecureBootRevocations.ps1
# Description: Triggers Secure Boot DBX and Code Integrity revocation updates for BlackLotus mitigation.

Write-Host "--- Configuring BlackLotus Secure Boot Mitigations ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Trigger updates (0x5944 = 22852)
Set-ItemProperty -Path $Path -Name "AvailableUpdates" -Value 22852 -Type DWord -Force | Out-Null
Write-Host "[+] BlackLotus DBX and 2023 CA revocation updates configured in registry. A system reboot is required." -ForegroundColor Green
```

---

### Audit Script

Run the following script to check the status of Secure Boot revocations on the local machine:

[Download Script: Audit-SecureBootRevocations.ps1](audit_scripts/Audit-SecureBootRevocations.ps1)

```powershell
# Audit-SecureBootRevocations.ps1
# Description: Queries UEFI Secure Boot parameters and audits BlackLotus mitigation registry settings.

Write-Host "--- Auditing BlackLotus Mitigations ---" -ForegroundColor Cyan

$script:NonCompliant = $false

# 1. Audit AvailableUpdates registry key
$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue
    $UpdateVal = if ($Val) { $Val.AvailableUpdates } else { 0 }
    
    # Check if configured (>= 0x4000 / 16384)
    if ($UpdateVal -ge 16384) {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Compliant)" -ForegroundColor Green
    } else {
        Write-Host "    - BlackLotus Revocation Updates (AvailableUpdates): $UpdateVal (Non-Compliant - DBX/SVN revocations not triggered)" -ForegroundColor Red
        $script:NonCompliant = $true
    }
} else {
    Write-Host "    - BlackLotus Revocation Updates: Registry path not found (Non-Compliant)" -ForegroundColor Red
    $script:NonCompliant = $true
}

# 2. Audit UEFICA2023Status (if present)
$ServicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
if (Test-Path $ServicingPath) {
    $ServVal = Get-ItemProperty -Path $ServicingPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue
    if ($ServVal) {
        $Status = $ServVal.UEFICA2023Status
        $Color = if ($Status -eq "Updated") { "Green" } else { "Yellow" }
        Write-Host "    - UEFI CA 2023 Update Status: $Status" -ForegroundColor $Color
    }
}

if ($script:NonCompliant) {
    exit 1
}
```

---

## Sources & Compliance References
* **Microsoft KB5068202**: Registry key updates for Secure Boot: Windows devices with IT-managed updates
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
