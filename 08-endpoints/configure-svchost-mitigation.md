# [REQ-END-030] Configure svchost.exe Mitigation Options

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations. *(For Domain Controllers and Domain Member Servers, refer to [REQ-DC-029](../02-domain-controllers/configure-svchost-mitigation.md); for Privileged Access Workstations, refer to [REQ-PAW-017](../07-paws/configure-svchost-mitigation.md)).*
* **Operating Systems**: Windows 10 (1903 and above), Windows 11 Enterprise/Professional.

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
The Service Host (`svchost.exe`) process is a fundamental Windows operating system binary designed to host one or more shared or isolated system services. Because `svchost.exe` instances execute with elevated privileges (such as `NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LOCAL SERVICE`, or `NT AUTHORITY\NETWORK SERVICE`) and naturally maintain persistent execution across user sessions, they represent one of the primary targets for threat actors seeking privilege escalation, defense evasion, and persistence on client workstations.

In client endpoint environments, workstations serve as the primary initial access vector for attackers through phishing attachments, malicious browser downloads, drive-by exploits, or compromised peripheral devices. Once a basic user-level foothold is achieved, adversaries frequently attempt to blend malicious activity into legitimate system traffic by targeting `svchost.exe`:
1. **Process Injection & Hollowing (MITRE ATT&CK T1055, T1055.012)**: Attackers create a suspended `svchost.exe` process or inject malicious code into an existing service host instance (`CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`). This disguises command-and-control (C2) beaconing (e.g., Cobalt Strike, Sliver, Brute Ratel) under trusted system process names and bypasses basic endpoint security inspection.
2. **Dynamic Code Execution & Reflective Loading**: In-memory payloads and exploitation frameworks rely on allocating executable memory (`PAGE_EXECUTE_READWRITE` via `VirtualAlloc` or `VirtualProtect`) to dynamically decrypt, compile, or inject unmapped DLLs directly into process memory without touching disk.
3. **Ghost Service DLL Hijacking & Malicious Service Registration (MITRE ATT&CK T1574.002)**: Attackers modify service registry keys to point `ServiceDll` to unsigned, arbitrary third-party DLLs. When the Service Control Manager starts the service, `svchost.exe` loads the unauthorized DLL with SYSTEM privileges.

Enabling `svchost.exe` mitigation options instructs the Windows Service Control Manager (SCM, `services.exe`) to apply strict kernel-enforced process creation mitigation policies whenever a new `svchost.exe` instance is spawned:
* **Microsoft-Only Binary Enforcement (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`)**: Enforces that every executable binary and Dynamic Link Library (DLL) loaded into the address space of any `svchost.exe` process must be digitally signed by a trusted Microsoft certificate (Windows Production Root, WHQL, or Microsoft Corporation). Any attempt by unsigned, self-signed, or third-party binaries to map into `svchost.exe` is immediately terminated by the Windows kernel with `STATUS_INVALID_IMAGE_HASH` (`0xC0000428`).
* **Dynamic Code Execution Blocking (`PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`)**: Disallows the generation and execution of dynamic code within `svchost.exe` processes. This kernel mitigation blocks arbitrary memory page execution, preventing JIT compilation abuse, shellcode execution, and reflective DLL injection inside all system service containers.
* **Service Host Splitting Synergies**: Since Windows 10 Version 1703, on workstations with more than 3.5 GB of RAM (`SvcHostSplitThresholdInKB`), Windows automatically isolates individual services into dedicated, standalone `svchost.exe` processes. When `EnableSvchostMitigationPolicy` is active, this per-service architecture ensures that every isolated service process receives independent, uncompromising mitigation enforcement.

---

## Legacy Impact & Compatibility
* **Third-Party Antivirus, EDR, and Management Agents**: Historically, Microsoft included `Enable svchost.exe mitigation options` in early Windows 10 security baselines (versions 1709 through 1909), but removed it from default baseline guidance starting with Windows 10 2004. Microsoft explicitly documented that while this control provides exceptional security value, several legacy third-party antivirus utilities, endpoint management suites, and specialized hardware smart card minidrivers were architected as custom DLL plugins loaded directly inside `svchost.exe`. When non-Microsoft binaries are blocked, non-compliant third-party services fail to start.
* **Modern Endpoint Posture**: Modern, supported enterprise software vendors (EDR agents, VPN clients, backup agents, printing utilities) run as independent standalone executables (`.exe`) or register isolated non-svchost service binaries. Organizations adopting an Active Directory hardening posture should enforce this setting on client endpoints after validating that all deployed management and security agents are compliant.
* **Operating System Support**: This policy is natively supported on Windows 10 version 1903 (Build 18362) and above, and Windows 11. It has no effect on Windows 10 versions prior to 1903.
* **Process Lifecycle & Reboot Prerequisite**: The Service Control Manager applies mitigation attributes only when creating a new `svchost.exe` process. While restarting individual services will apply the policy to new instances, core system services initialized during the early kernel boot phase remain unmitigated until the endpoint undergoes a **system restart**.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on an administrative workstation or Domain Controller.
2. Create a new GPO or edit an existing endpoint hardening GPO (e.g., `GPO_Hardening_Tier2_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
4. In the right-hand details pane, double-click **Enable svchost.exe mitigation options**.
5. Select **Enabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the Organizational Unit (OU) containing your Tier 2 client workstations (e.g., `OU=Workstations,DC=contoso,DC=com`).
8. After applying the policy, schedule or initiate a system restart on target endpoints to enforce the mitigation policy across all boot-level service host instances.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally during gold master image creation, automated Intune / MDM provisioning, or standalone testing.

[Download Script: Configure-SvchostMitigation.ps1](implementation_scripts/Configure-SvchostMitigation.ps1)

```powershell
# Configure-SvchostMitigation.ps1
# Description: Configures svchost.exe mitigation options to enforce Microsoft-signed binaries and block dynamic code.

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

Write-Host "Applying hardening requirement: Configure svchost.exe mitigation options..." -ForegroundColor Cyan

# Verify minimum operating system build compatibility (Windows 10 1903 / Build 18362 or Windows Server 2022 / Build 20348)
$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "The operating system build ($($osBuild)) does not support EnableSvchostMitigationPolicy (requires Windows 10 1903+ or Windows Server 2022+)."
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
    Write-Error "Error configuring svchost.exe mitigation options: $($_.Exception.Message)"
    exit 1
}
```

*To verify the setting has been applied:*

[Download Script: Get-SvchostMitigationStatus.ps1](audit_scripts/Get-SvchostMitigationStatus.ps1)

```powershell
# Get-SvchostMitigationStatus.ps1
# Description: Audits the configuration state of svchost.exe mitigation options.

[CmdletBinding()]
param()

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SCMConfig"
$ValueName = "EnableSvchostMitigationPolicy"
$ExpectedValue = 1

Write-Host "Auditing hardening requirement: Configure svchost.exe mitigation options..." -ForegroundColor Cyan

$osVersion = [System.Environment]::OSVersion.Version
$osBuild = $osVersion.Build

if ($osBuild -lt 18362) {
    Write-Warning "Audit Result: Non-Applicable / Unsupported. OS build $($osBuild) precedes the introduction of svchost mitigation policy (requires Windows 10 1903+ or Windows Server 2022+)."
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

When `EnableSvchostMitigationPolicy` is active, Windows kernel code integrity and the Service Control Manager generate high-fidelity event log entries if any process or unsigned binary violates the policy:

| Log Channel | Event ID | Event Source | Description & Operational Significance |
| :--- | :--- | :--- | :--- |
| **System** | `7000` | `Service Control Manager` | Service failed to start because the binary or service DLL failed digital signature validation. |
| **System** | `7023` / `7024` | `Service Control Manager` | A running service terminated prematurely due to an invalid image hash error (`0x80070428` / `ERROR_INVALID_IMAGE_HASH`). |
| **Microsoft-Windows-Security-Mitigations/KernelMode** | `1` | `Security-Mitigations` | Kernel-level process mitigation enforcement event. Triggered when an in-memory dynamic code generation attempt is blocked inside `svchost.exe`. |
| **Microsoft-Windows-CodeIntegrity/Operational** | `3033` | `CodeIntegrity` | Enforced block event. Triggered when `svchost.exe` attempts to load a DLL that does not satisfy Microsoft Authenticode signing criteria. |
| **Microsoft-Windows-CodeIntegrity/Operational** | `3077` | `CodeIntegrity` | Audit-mode event indicating a non-compliant or unsigned binary load was attempted in a service host container. |

---

## Sources & Compliance References
* **Microsoft Learn**: [Service Control Manager Settings](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10#service-control-manager-settings)
* **Microsoft Security Guidance**: [Why SCM svchost mitigation was retired from default baseline](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-10-version-2004-and-windows-server/ba-p/1460395)
* **CIS Microsoft Windows Client Benchmark**: Section 18.9.30.1 - Ensure 'Enable svchost.exe mitigation options' is set to 'Enabled'
* **MITRE ATT&CK Matrix**:
  * [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
  * [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
  * [T1574.002 - Hijack Execution Flow: DLL Side-Loading / Service DLL](https://attack.mitre.org/techniques/T1574/002/)
