# [REQ-END-021] Restrict Safe Mode Access to Administrators

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Location**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
    * **Value Name**: `SafeModeBlockNonAdmins`
    * **Value Type**: `REG_DWORD`
    * **Value Data**: `1`

---

## Rationale
Malicious actors with standard user credentials can potentially bypass local security policies, local endpoint detection and response (EDR) agents, and group policy restrictions by booting the system into Safe Mode. In Safe Mode, many security agents and services do not load, creating an environment where local controls can be circumvented.

By configuring `SafeModeBlockNonAdmins = 1`:
1. **Prevent Credential Bypass**: Standard users are blocked from logging in during Safe Mode, ensuring they cannot exploit the disabled security agents to execute unauthorized programs or extract system information.
2. **Maintenance Integrity**: Safe Mode remains accessible exclusively to system administrators for debugging and recovery, ensuring administrative capability is preserved while mitigating standard user risk.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: This setting does not affect local or domain administrative accounts, which can still log in normally to perform repairs.
* **Troubleshooting Availability**: If a standard user experiences system issues that require Safe Mode, an administrator must log in to the workstation to troubleshoot, which may slightly increase administrative overhead.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Because there is no native Administrative Template (ADMX) policy for this setting, it must be deployed using Group Policy Preferences (GPP) to configure the registry directly.

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Right-click in the right pane, select **New** > **Registry Item**, and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
   * **Value Name**: `SafeModeBlockNonAdmins`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target client endpoints and member servers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on standalone systems or during reference image build phases.

[Download Script: Configure-DisableSafeModeNonAdmins.ps1](implementation_scripts/Configure-DisableSafeModeNonAdmins.ps1)

```powershell
# Configure-DisableSafeModeNonAdmins.ps1
# Description: Prevents standard users from logging into the system while in Safe Mode by setting SafeModeBlockNonAdmins to 1.

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "SafeModeBlockNonAdmins"
$ValueData = 1

Write-Host "Applying hardening requirement: Restrict Safe Mode access to administrators..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force | Out-Null
Write-Host "Hardening applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-SafeModeNonAdminsStatus.ps1](audit_scripts/Get-SafeModeNonAdminsStatus.ps1)

```powershell
# Get-SafeModeNonAdminsStatus.ps1
# Description: Checks the current configuration state of SafeModeBlockNonAdmins registry setting.

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$ValueName = "SafeModeBlockNonAdmins"

Write-Host "Auditing hardening requirement: Restrict Safe Mode access to administrators..." -ForegroundColor Cyan

if (Test-Path $RegPath) {
    $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$ValueName -eq 1) {
        Write-Host "Audit Result: Compliant. Standard users are blocked from logging in during Safe Mode ($ValueName = 1)." -ForegroundColor Green
        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. Standard users are allowed to log in during Safe Mode." -ForegroundColor Red
exit 1
```

---

## Sources & Compliance References
* **Australian Cyber Security Centre (ACSC) / ASD**: Windows Hardening Guidelines (SafeModeBlockNonAdmins configuration).
* **Microsoft Learn**: Windows policies and registry-based mitigations.
