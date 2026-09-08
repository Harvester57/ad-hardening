# [REQ-DC-029] Configure svchost.exe Mitigation Options

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0) and Domain Member Servers (Tier 1). *(For Privileged Access Workstations, refer to [REQ-PAW-017](../07-paws/configure-svchost-mitigation.md); for Tier 2 Client Workstations, refer to [REQ-END-030](../08-endpoints/configure-svchost-mitigation.md)).*
* **Operating Systems**: Windows Server 2022, Windows Server 2025, Windows Server Semi-Annual Channel (1903 and above).

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
The Service Host (`svchost.exe`) process is an essential operating system component responsible for hosting multiple background services in Windows. Because `svchost.exe` processes execute with the highest operating system privileges (typically `NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LOCAL SERVICE`, or `NT AUTHORITY\NETWORK SERVICE`), they represent high-value targets for adversaries seeking privilege escalation, persistence, and defense evasion across both Domain Controllers and enterprise Domain Member Servers.

### 1. Domain Controllers (Tier 0 Identity Infrastructure)
On Active Directory Domain Controllers, `svchost.exe` instances host critical directory, identity, and network management services:
* **Kerberos Key Distribution Center (`Kdc`)**: Issues Kerberos ticket-granting tickets (TGTs) and service tickets.
* **Security Accounts Manager (`SamSs`)**: Manages account databases and security principles.
* **Netlogon Service (`Netlogon`)**: Maintains secure channels with member computers and authenticates domain logons.
* **Active Directory Integrated DNS (`DNS`)**: Resolves domain records and service location records (SRV).
* **Windows Time Service (`W32Time`)**: Synchronizes domain-wide Kerberos timestamps.

Because Domain Controllers are strictly dedicated identity systems that should never run non-essential third-party applications, web browsers, or productivity suites, enforcing `svchost.exe` process mitigations carries minimal operational risk while shutting down major post-exploitation vectors. Attackers attempting to leverage compromised domain accounts to drop unsigned malicious DLLs (such as rogue `ServiceDll` implants) or inject shellcode directly into DC service hosts are intercepted and blocked by the kernel.

### 2. Domain Member Servers (Tier 1 Enterprise Workloads)
Enterprise Domain Member Servers host application workloads, database instances (SQL Server), web servers (IIS), file repositories, and IT management agents. In standard lateral movement playbooks:
* **Living-off-the-Land & Evasion**: Attackers pivot from compromised workstations to member servers, using process injection (`CreateRemoteThread`, `QueueUserAPC`, `SetThreadContext`) to disguise C2 beacons and malicious activity under legitimate `svchost.exe` instances.
* **Dynamic Code Execution**: Threat frameworks allocate executable memory pages (`PAGE_EXECUTE_READWRITE`) to decrypt and execute in-memory shellcode without creating files on disk.
* **Malicious Service Registration (MITRE ATT&CK T1574.002)**: Adversaries establish persistence on member servers by modifying registry keys under `HKLM\System\CurrentControlSet\Services` to point `ServiceDll` to an unsigned backdoor DLL.

### Technical Mitigation Mechanics
Enabling `EnableSvchostMitigationPolicy` instructs the Service Control Manager (SCM, `services.exe`) to configure Windows kernel process mitigation attributes (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`) whenever spawning any `svchost.exe` instance:
1. **Microsoft-Only Binary Enforcement (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`)**:
   Mandates that every binary and Dynamic Link Library (DLL) loaded into the address space of `svchost.exe` must be digitally signed by a valid Microsoft certificate. Any unsigned, self-signed, or third-party binary attempting to map into `svchost.exe` fails with `STATUS_INVALID_IMAGE_HASH` (`0xC0000428`).
2. **Prohibit Dynamic Code Execution (`PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`)**:
   Blocks the generation and execution of dynamic code within `svchost.exe` processes. This prevents arbitrary executable memory page allocations (`VirtualAlloc` with `PAGE_EXECUTE*`), neutralizing JIT compilation abuse, reflective DLL loading, and in-memory shellcode staging.
3. **Per-Service Host Isolation**:
   On Windows Server 2022 and 2025 systems with more than 3.5 GB of RAM, services run in separate, dedicated `svchost.exe` processes. This ensures that a failure or mitigation block in one service container cannot compromise other unrelated system services.

---

## Legacy Impact & Compatibility

### Tier 0 Domain Controllers vs. Tier 1 Member Servers
* **Domain Controllers (Tier 0)**: Extremely low compatibility risk. Active Directory Domain Services, DNS, Kerberos KDC, and native Windows Server roles use 100% Microsoft-signed binaries and do not rely on dynamic code generation.
* **Domain Member Servers (Tier 1)**: Moderate compatibility risk. While modern enterprise software runs as independent executables (`.exe`), certain legacy third-party management utilities, hardware monitoring agents, or outdated antivirus plugins historically registered as service DLLs loaded directly inside `svchost.exe`. If a non-Microsoft DLL is configured as a `ServiceDll` inside a shared svchost group, that service will fail to initialize.

### Pre-Deployment Compatibility Audit for Member Servers
Before enforcing this control across production Domain Member Server OUs, run the following PowerShell command on representative member servers to verify whether any third-party, non-Microsoft service DLLs are registered under `svchost.exe`:

```powershell
# Enumerate all svchost-hosted service DLLs and inspect digital signatures
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\*\Parameters" -Name "ServiceDll" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $dllPath = [Environment]::ExpandEnvironmentVariables($_.ServiceDll)
        if (Test-Path -Path $dllPath) {
            $sig = Get-AuthenticodeSignature -FilePath $dllPath
            if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notlike "*CN=Microsoft Corporation*") {
                [PSCustomObject]@{
                    ServicePath = $_.PSPath
                    ServiceDll  = $dllPath
                    Signer      = $sig.SignerCertificate.Subject
                    Status      = $sig.Status
                }
            }
        }
    }
```

### Operating System Support & Limitations
* **Windows Server 2022 / 2025**: Fully supported natively via the SCM `EnableSvchostMitigationPolicy` registry setting and Group Policy.
* **Windows Server 2016 / 2019**: These operating system builds (Build 14393 and 17763) precede the introduction of the SCM `EnableSvchostMitigationPolicy` setting. The registry value will have no operational effect on Windows Server 2016 or 2019. On those platforms, organizations should utilize Windows Defender Application Control (WDAC) driver blocklists ([REQ-DC-022](enable-wdac-driver-blocklist.md)) and AppLocker policies ([REQ-DC-021](configure-applocker-policies.md)) to restrict binary execution.
* **Reboot Requirement**: SCM applies mitigation options at process creation time. While restarting individual services will enforce policies on new instances, core system services launched during initial system startup remain unmitigated until a **system restart** is performed.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To ensure operational stability and permit phased deployment, configure separate GPOs for Tier 0 Domain Controllers and Tier 1 Member Servers.

#### 1. Configure GPO for Domain Controllers (Tier 0)
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a Domain Controller or management workstation.
2. Edit the baseline Domain Controller hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
4. Double-click **Enable svchost.exe mitigation options**.
5. Select **Enabled**.
6. Click **Apply**, then **OK**.
7. Link the GPO to the **Domain Controllers** Organizational Unit (`OU=Domain Controllers,DC=contoso,DC=com`).

#### 2. Configure GPO for Domain Member Servers (Tier 1)
1. In `gpmc.msc`, edit the baseline Member Server hardening GPO (e.g., `GPO_Hardening_MemberServers`).
2. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Service Control Manager Settings\Security Settings`
3. Configure **Enable svchost.exe mitigation options** to **Enabled**.
4. Link the GPO to your **Member Servers** Organizational Units (e.g., `OU=Tier1_Servers,OU=Servers,DC=contoso,DC=com`).
5. Stage deployment across non-production and pilot server groups before enabling domain-wide.
6. Perform a scheduled server restart during an authorized maintenance window to apply process mitigations across all system services.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally during base image creation, automated provisioning, or standalone server testing.

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
    Write-Warning "The operating system build ($($osBuild)) does not support EnableSvchostMitigationPolicy (requires Windows Server 2022+ or Windows 10 1903+)."
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
    Write-Warning "Audit Result: Non-Applicable / Unsupported. OS build $($osBuild) precedes the introduction of svchost mitigation policy (requires Windows Server 2022+ or Windows 10 1903+)."
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

When `EnableSvchostMitigationPolicy` is active on servers, monitor the following event logs for policy violations, blocked DLL loads, or dynamic code execution attempts:

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
* **Microsoft Security Guidance**: [Security baseline for Windows Server and Windows 10](https://techcommunity.microsoft.com/t5/microsoft-security-baselines/security-baseline-for-windows-10-version-2004-and-windows-server/ba-p/1460395)
* **ANSSI AD Hardening Guide**: Section 3.2 - Service and System Process Hardening
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 18.9.30.1 - Ensure 'Enable svchost.exe mitigation options' is set to 'Enabled'
* **MITRE ATT&CK Matrix**:
  * [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
  * [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
  * [T1574.002 - Hijack Execution Flow: DLL Side-Loading / Service DLL](https://attack.mitre.org/techniques/T1574/002/)
