# [REQ-PAW-017] Configure svchost.exe Mitigation Options for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs). *(For Domain Controllers and Domain Member Servers, refer to [REQ-DC-029](../02-domain-controllers/configure-svchost-mitigation.md); for Tier 2 Client Workstations, refer to [REQ-END-030](../08-endpoints/configure-svchost-mitigation.md)).*
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
Privileged Access Workstations (PAWs) host the most sensitive administrative credentials in an Active Directory environment, including Tier 0 Domain Admin Kerberos tickets, directory service RPC sessions, and PKI private key operations. Because PAWs are dedicated, single-purpose administrative endpoints, securing the Service Host (`svchost.exe`) process is critical to preventing kernel-level security evasion, process injection, and credential theft.

Adversaries attempting to compromise administrative sessions frequently target `svchost.exe`:
1. **Process Injection & Credential Harvesting**: Infiltrating an administrative session by injecting into a high-privilege `svchost.exe` process (`CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`) allows attackers to execute shellcode within the `NT AUTHORITY\SYSTEM` security context, evading endpoint monitoring and attempting to access memory spaces holding privileged administrative tokens.
2. **Reflective DLL Loading & Dynamic Code Execution**: Advanced persistent threat (APT) frameworks execute memory-only payloads by allocating executable memory (`VirtualAlloc` with `PAGE_EXECUTE_READWRITE`) to bypass disk-based file scanners.
3. **Ghost Service Implants (MITRE ATT&CK T1574.002)**: Dropping unsigned service DLLs and registering them under legitimate `svchost.exe` service groups to gain persistent administrative access.

Enabling `svchost.exe` mitigation options on PAWs restricts the behavior of every `svchost.exe` process through kernel-level mitigation policies:
* **Microsoft-Only Binary Enforcement (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`)**: Requires all binaries and dynamic-link libraries (DLLs) loaded into `svchost.exe` to be digitally signed by Microsoft. This prevents attackers from injecting custom, unsigned malicious DLLs into `svchost.exe` instances to tamper with administrative service processes. Any attempt to load non-Microsoft code is blocked with `STATUS_INVALID_IMAGE_HASH` (`0xC0000428`).
* **Dynamic Code Execution Blocking (`PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`)**: Disallows the generation and execution of dynamic code within `svchost.exe` processes. This neutralizes in-memory shellcode execution, JIT compilation abuse, and typical process hollowing attack vectors.
* **Service Host Isolation**: On modern Windows 10/11 Enterprise systems with more than 3.5 GB of RAM, services run in separate, dedicated `svchost.exe` processes, ensuring each administrative service host is strictly isolated and independently enforced.

---

## Legacy Impact & Compatibility
* **Third-Party Compatibility**: This policy requires all binaries loaded by `svchost.exe` to be Microsoft-signed. Because PAWs are strictly controlled, single-purpose administrative workstations, they must run minimal third-party software. However, any third-party management agents, smart card reader drivers, or security software that attempt to execute service DLLs inside the `svchost.exe` process space using non-Microsoft DLLs will fail to load.
* **Administrative Tooling**: Standard Microsoft administrative tools (RSAT, Active Directory Administrative Center, DNS Manager, MMC snap-ins, PowerShell 5.1/7.x) run completely cleanly under this mitigation.
* **Operating System Support**: This policy is natively supported on Windows 10 version 1903 (Build 18362) and above, and Windows 11 Enterprise.
* **Process Lifecycle & Reboot Prerequisite**: The Service Control Manager applies mitigation attributes only when creating a new `svchost.exe` process. While restarting individual services will apply the policy to new instances, core system services initialized during the early kernel boot phase remain unmitigated until the PAW undergoes a **system restart**.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a PAW or Domain Controller.
2. Edit the dedicated PAW hardening GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
4. Double-click **Enable svchost.exe mitigation options**.
5. Select **Enabled**.
6. Click **Apply**, then **OK**.
7. Link the GPO to the dedicated **PAW** Organizational Unit (`OU=PAW,OU=Tier0,DC=contoso,DC=com`).
8. Reboot the target PAW systems to ensure the mitigation policy is actively enforced across all system services.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally on standalone PAWs or during initial reference image provisioning.

[Download Script: Configure-SvchostMitigation.ps1](implementation_scripts/Configure-SvchostMitigation.ps1)

```powershell
# Configure-SvchostMitigation.ps1
# Description: Configures svchost.exe mitigation options to enforce Microsoft-signed binaries and block dynamic code on PAWs.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Applying hardening requirement: Configure svchost.exe mitigation options for PAWs..." -ForegroundColor Cyan

# Verify minimum operating system build compatibility (Windows 10 1903 / Build 18362 or Windows 11)
$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "The operating system build ($($osBuild)) does not support EnableSvchostMitigationPolicy (requires Windows 10 1903+ or Windows 11)."
    exit 1
}

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ValueData = 1

try {
    if (-not (Test-Path -Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
        Write-Host "Created registry key: $($RegPath)" -ForegroundColor Gray
    }

    Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord -Force | Out-Null

    # Validate written value
    $configuredValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
    if ($configuredValue -eq $ValueData) {
        Write-Host "Hardening applied successfully: $($ValueName) set to 1." -ForegroundColor Green
        Write-Host "Note: This policy applies to newly created svchost.exe instances. A full system restart is required to protect services initialized at system boot." -ForegroundColor Yellow
        exit 0
    } else {
        throw "Failed to verify registry property value after write."
    }
} catch {
    Write-Error "Error configuring svchost.exe mitigation options on PAW: $($_.Exception.Message)"
    exit 1
}
```

*To verify the setting has been applied:*

[Download Script: Get-SvchostMitigationStatus.ps1](audit_scripts/Get-SvchostMitigationStatus.ps1)

```powershell
# Get-SvchostMitigationStatus.ps1
# Description: Audits the configuration state of svchost.exe mitigation options on PAWs.

[CmdletBinding()]
param()

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ExpectedValue = 1

Write-Host "Auditing hardening requirement: Configure svchost.exe mitigation options on PAW..." -ForegroundColor Cyan

$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "Audit Result: Non-Applicable / Unsupported. OS build $($osBuild) precedes the introduction of svchost mitigation policy (requires Windows 10 1903+ or Windows 11)."
    exit 1
}

if (Test-Path -Path $RegPath) {
    $item = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $item -and $item.$ValueName -eq $ExpectedValue) {
        Write-Host "Audit Result: Compliant. svchost.exe mitigation policy is enabled in registry ($($RegPath)\$($ValueName) = 1)." -ForegroundColor Green

        # Optional check for running svchost processes
        $svchostProcesses = Get-Process -Name "svchost" -ErrorAction SilentlyContinue
        if ($svchostProcesses) {
            Write-Host "Found $($svchostProcesses.Count) running svchost.exe process instances. Process mitigation flags are enforced dynamically at process spawn by the Service Control Manager." -ForegroundColor Gray
        }

        exit 0
    }
}

Write-Host "Audit Result: Non-Compliant. svchost.exe mitigation options are disabled or not configured ($($RegPath)\$($ValueName))." -ForegroundColor Red
exit 1
```

---

## Auditing & Detection Telemetry

When `EnableSvchostMitigationPolicy` is active on PAWs, monitor the following event logs for policy violations, blocked DLL loads, or dynamic code execution attempts:

| Log Channel | Event ID | Event Source | Description & Operational Significance |
| :--- | :--- | :--- | :--- |
| **System** | `7000` | `Service Control Manager` | Service failed to start because the service DLL failed digital signature validation. |
| **System** | `7023` / `7024` | `Service Control Manager` | Running service terminated unexpectedly due to an invalid image hash (`0x80070428` / `ERROR_INVALID_IMAGE_HASH`). |
| **Microsoft-Windows-Security-Mitigations/KernelMode** | `1` | `Security-Mitigations` | Kernel process mitigation event indicating dynamic code generation was blocked inside `svchost.exe`. |
| **Microsoft-Windows-CodeIntegrity/Operational** | `3033` | `CodeIntegrity` | Enforced block event. `svchost.exe` was blocked from loading a DLL that does not meet Microsoft Authenticode signature requirements. |
| **Microsoft-Windows-CodeIntegrity/Operational** | `3077` | `CodeIntegrity` | Audit-mode event indicating an unsigned or third-party binary load was attempted in a service host container. |

---

## Sources & Compliance References
* **Microsoft Learn**: [Service Control Manager Settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10#service-control-manager-settings)
* **Microsoft Security Guidance**: [Security baseline for Windows 10 and PAW deployments](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-10-version-2004-and-windows-server/ba-p/1460395)
* **CIS Microsoft Windows Client Benchmark**: Section 18.9.30.1 - Ensure 'Enable svchost.exe mitigation options' is set to 'Enabled'
* **MITRE ATT&CK Matrix**:
  * [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
  * [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
  * [T1574.002 - Hijack Execution Flow: DLL Side-Loading / Service DLL](https://attack.mitre.org/techniques/T1574/002/)
