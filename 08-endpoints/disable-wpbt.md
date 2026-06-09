# Hardening Requirement: Disable Windows Platform Binary Table (WPBT)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * Computer Configuration\Preferences\Windows Settings\Registry
  * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\DisableWpbtExecution

---

## Rationale
The Windows Platform Binary Table (WPBT) is an ACPI firmware table that allows hardware manufacturers (OEMs) to execute proprietary binaries in kernel space during the Windows boot phase. Windows automatically extracts the binary from the table and runs it with system privileges before security software, third-party agents, or standard driver verifications are fully initialized.

While designed to facilitate automated driver provisioning and anti-theft services, this mechanism represents a significant security risk:
1. **Firmware-to-OS Attack Vector**: Malicious actors utilizing UEFI rootkits, physical firmware flashing tools, or supply-chain firmware implants can compromise the WPBT table to execute arbitrary code at boot, bypassing Secure Boot and operating system-level integrity checks.
2. **Privilege Escalation Risks**: Historically, OEM software delivered via the WPBT has introduced high-severity local privilege escalation and remote code execution vulnerabilities due to inadequate code review or poor permission management.
3. **Control and Transparency**: Executing firmware-rooted binaries without administrative visibility or operating system validation bypasses normal software lifecycle and endpoint protection policies.

Disabling WPBT execution prevents Windows from parsing the ACPI table and running the embedded software, mitigating boot-level integrity bypasses.

---

## Legacy Impact & Compatibility
* **OEM Software Functionality**: Disabling the WPBT will stop manufacturer-embedded software (such as automated support assistants, system registration tools, or OEM-specific recovery software) from installing on a fresh OS deployment. System installation pipelines must manually deploy any validated, business-essential hardware utility packages rather than relying on automatic firmware injection.
* **Deployment Timing**: The registry setting `DisableWpbtExecution` must be present prior to the initial Windows boot sequence to completely block WPBT payload execution on a newly installed OS. Applying the registry key via GPO will prevent subsequent runs or updates but will not retroactively clean up files that were already executed during the initial setup. For maximum protection, this registry modification should be integrated directly into reference installation media (e.g., via `autounattend.xml` or custom WIM injection).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Because there is no default ADMX administrative template to manage WPBT execution, the setting must be configured as a Registry Preference under the endpoint policy:

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain management host.
2. Edit the GPO linked to your workstations Organizational Unit (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Right-click **Registry**, select **New -> Registry Item**.
5. Configure the following properties:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager`
   * **Value name**: `DisableWpbtExecution`
   * **Value type**: `REG_DWORD`
   * **Value data**: `1`
6. Click **OK** to save the preference.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to configure the registry setting locally on the system:

```powershell
# Configure-DisableWpbt.ps1
# Description: Disables Windows Platform Binary Table (WPBT) execution in the registry.

Write-Host "Applying hardening requirement: Disable WPBT Execution..." -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$ValueName = "DisableWpbtExecution"
$ValueData = 1

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord
Write-Host "Registry setting DisableWpbtExecution configured to 1." -ForegroundColor Green
```

*To verify that the registry value is correctly enforced:*

```powershell
# Get-WpbtStatus.ps1
# Description: Audits the registry state for WPBT execution prevention.

Write-Host "--- Auditing WPBT Security Posture ---" -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
$ValueName = "DisableWpbtExecution"

$RegistryValue = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue

if ($RegistryValue) {
    $Setting = $RegistryValue.DisableWpbtExecution
    if ($Setting -eq 1) {
        Write-Host "Status: WPBT execution is disabled (DisableWpbtExecution = 1)." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: WPBT execution is enabled. Value is $($Setting)." -ForegroundColor Red
    }
} else {
    Write-Host "VULNERABLE: DisableWpbtExecution registry value is not configured (defaulting to execution enabled)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations regarding hardware platform integrity.
* **Microsoft Windows Security**: Device Guard and UEFI Platform Security guidelines.
