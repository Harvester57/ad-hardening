# [REQ-PAW-017] Configure svchost.exe Mitigation Options for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs).
* **Operating Systems**: Windows 10 (1903 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings\Enable svchost.exe mitigation options`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\SCMConfig`
    * **Value Name**: `EnableSvchostMitigationPolicy`
    * **Value Type**: `REG_DWORD`
    * **Value Data**: `1`

---

## Rationale
Privileged Access Workstations (PAWs) host highly sensitive administrative sessions and credentials. Securing the Service Host (`svchost.exe`) process is critical to preventing kernel-level security evasion and credential harvesting techniques.

Enabling `svchost.exe` mitigation options on PAWs restricts the behavior of the `svchost.exe` process to enhance security:
1. **Microsoft-Only Binary Enforcement**: Requires all binaries and dynamic-link libraries (DLLs) loaded into `svchost.exe` to be digitally signed by Microsoft. This prevents attackers from injecting custom, unsigned malicious DLLs into `svchost.exe` instances to tamper with administrative service processes.
2. **Dynamic Code Blocking**: Prevents the execution of dynamically generated code (such as Just-In-Time compiled code) within `svchost.exe` processes, neutralizing typical in-memory exploitation vectors.

---

## Legacy Impact & Compatibility
* **Third-Party Compatibility**: This policy requires all binaries loaded by `svchost.exe` to be Microsoft-signed. Since PAWs are strictly controlled, single-purpose administrative machines, they should run minimal third-party software. However, any security tools, smart card readers, or system drivers that attempt to run services inside the `svchost.exe` process space using non-Microsoft DLLs will fail to load.
* **Operating System Support**: This policy has no effect on Windows 10 versions prior to 1903.
* **Deployment Validation**: Ensure that any administrative agents or hardware verification drivers are fully certified and Microsoft-signed before enforcing this control.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
4. Configure the following setting:
   * **Policy**: `Enable svchost.exe mitigation options`
   * **Setting**: `Enabled`
5. Link the GPO to the PAW Organizational Unit (OU) containing the target systems.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on standalone systems or during reference image build phases.

[Download Script: Configure-SvchostMitigation.ps1](implementation_scripts/Configure-SvchostMitigation.ps1)

```powershell
# Configure-SvchostMitigation.ps1
# Description: Configures svchost.exe mitigation options to enforce Microsoft-signed binaries and block dynamic code on PAWs.

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ValueData = 1

Write-Host "Applying hardening requirement: Configure svchost.exe mitigation options..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force | Out-Null
Write-Host "Hardening applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-SvchostMitigationStatus.ps1](audit_scripts/Get-SvchostMitigationStatus.ps1)

```powershell
# Get-SvchostMitigationStatus.ps1
# Description: Audits the configuration state of svchost.exe mitigation options on PAWs.

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ExpectedValue = 1

Write-Host "Auditing hardening requirement: Configure svchost.exe mitigation options..." -ForegroundColor Cyan

if (Test-Path $RegPath) {
    $value = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $value -and $value.$ValueName -eq $ExpectedValue) {
        Write-Host "Audit Result: Compliant. svchost.exe mitigation options are enabled." -ForegroundColor Green
        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. svchost.exe mitigation options are disabled or not configured." -ForegroundColor Red
exit 1
```

---

## Sources & Compliance References
* **Microsoft Learn**: Group Policy settings reference - Service Control Manager Settings
* **Microsoft Security Guidance**: Removing "Enable svchost.exe mitigation options" from baseline recommendations (for compatibility awareness)
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark (Section 18.9.30.1 - Mitigation Options reference)
