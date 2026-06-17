# [REQ-END-030] Configure svchost.exe Mitigation Options

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations.
* **Operating Systems**: Windows 10 (1903 and above), Windows 11 Enterprise/Professional.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings\Enable svchost.exe mitigation options`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Control\SCMConfig`
    * **Value Name**: `EnableSvchostMitigationPolicy`
    * **Value Type**: `REG_DWORD`
    * **Value Data**: `1`

---

## Rationale
The Service Host (`svchost.exe`) process runs multiple system services. Because these services execute with high privileges, they are frequently targeted for process injection, hollowing, or spoofing to execute arbitrary code or harvest credentials.

Enabling `svchost.exe` mitigation options restricts the behavior of the `svchost.exe` process to enhance security:
1. **Microsoft-Only Binary Enforcement**: Requires all binaries and dynamic-link libraries (DLLs) loaded into `svchost.exe` to be digitally signed by Microsoft. This prevents attackers from injecting custom, unsigned malicious DLLs into `svchost.exe` instances.
2. **Dynamic Code Blocking**: Prevents the execution of dynamically generated code (such as Just-In-Time compiled code) within `svchost.exe` processes, neutralizing typical in-memory exploitation vectors.

---

## Legacy Impact & Compatibility
* **Third-Party Compatibility**: This policy requires all binaries loaded by `svchost.exe` to be Microsoft-signed. Any third-party software, security agents, or system drivers that attempt to run services inside the `svchost.exe` process space using non-Microsoft DLLs will fail to load. This has historically caused issues with legacy antivirus, third-party authentication plugins, or specialized management utilities on client systems.
* **Operating System Support**: This policy has no effect on Windows 10 versions prior to 1903.
* **Deployment Validation**: It is recommended to perform extensive baseline testing on a representative subset of workstations running third-party software before deploying this configuration across the entire production domain.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain controller or management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
4. Configure the following setting:
   * **Policy**: `Enable svchost.exe mitigation options`
   * **Setting**: `Enabled`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target client endpoints.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on standalone systems or during reference image build phases.

[Download Script: Configure-SvchostMitigation.ps1](implementation_scripts/Configure-SvchostMitigation.ps1)

```powershell
# Configure-SvchostMitigation.ps1
# Description: Configures svchost.exe mitigation options to enforce Microsoft-signed binaries and block dynamic code.

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
# Description: Audits the configuration state of svchost.exe mitigation options.

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
