# [REQ-OPS-011] Enable Detailed BSOD Stop Parameters for Crash Control

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11 Enterprise

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Control\CrashControl`
  * **Registry Value**: `DisplayParameters` (REG_DWORD = `1`)

---

## Rationale
During critical system failures (such as a kernel panic or Blue Screen of Death - BSOD), Windows by default displays a simplified error screen intended for general consumers, hiding the actual bugcheck code and parameters.

Enabling detailed stop error parameters is crucial because:
1. **Offline Diagnostics**: In air-gapped, isolated environments, administrators cannot easily query online resources, transmit automated memory dumps, or contact cloud support.
2. **Immediate Visibility**: Having the exact stop code (e.g., `0x0000000A`) and the four parameters visible on the screen or virtual console allows operators to diagnose driver, memory, or hardware issues immediately.
3. **Improves Mean Time to Recovery (MTTR)**: Speeds up troubleshooting during disaster recovery or critical server restore processes.

---

## Legacy Impact & Compatibility
* **User Experience**: The screen display layout changes slightly when a crash occurs to show standard troubleshooting parameters. There is no impact on active system performance, running services, or application operations.
* **Troubleshooting dependencies**: Enabling this value does not affect the creation of memory dump files (minidumps or full dumps), which remain governed by other CrashControl parameters.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration

Because this parameter resides in the system registry and is not exposed as a default administrative template, it must be deployed via Group Policy Preferences (GPP):

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management station.
2. Create a new GPO targeting all domain computers (e.g., `GPO_Global_Config_SystemHardening`) or edit an existing policy.
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Right-click the **Registry** node and select **New** -> **Registry Item**.
5. Configure the following properties:
   * **Action**: Update
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\CrashControl`
   * **Value Name**: `DisplayParameters`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
6. Click **OK**.
7. Link the GPO to the top-level OU structure containing computers, servers, and Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script block to enable detailed stop error parameters locally in the registry.

[Download Script: Set-CrashControl.ps1](implementation_scripts/Set-CrashControl.ps1)

```powershell
# Set-CrashControl.ps1
# Description: Enables detailed BSOD parameters in the registry.

Write-Host "--- Configuring Detailed BSOD Parameters ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

Set-ItemProperty -Path $Path -Name "DisplayParameters" -Value 1 -Type DWord -Force | Out-Null
Write-Host "[+] Detailed BSOD stop parameters configured successfully." -ForegroundColor Green
```

*To verify that detailed stop parameters are enabled:*

[Download Script: Audit-CrashControl.ps1](audit_scripts/Audit-CrashControl.ps1)

```powershell
# Audit-CrashControl.ps1
# Description: Audits whether detailed BSOD parameters are enabled in the registry.

Write-Host "--- Auditing Detailed BSOD Parameters ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
if (Test-Path $Path) {
    $Val = Get-ItemProperty -Path $Path -Name "DisplayParameters" -ErrorAction SilentlyContinue
    if ($Val -and $Val.DisplayParameters -eq 1) {
        Write-Host "[+] Detailed BSOD stop parameters are ENABLED (Compliant)." -ForegroundColor Green
    } else {
        Write-Host "[-] Detailed BSOD stop parameters are DISABLED (Non-Compliant)." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[-] Registry path HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl not found." -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **Microsoft Security Guidance**: Windows CrashControl Registry Reference
* **ANSSI AD Hardening Guide**: Section 9 (Operations & Troubleshooting guidance)
