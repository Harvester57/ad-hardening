# [REQ-PAW-141] User Profile: Directory Protection Mode for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-152](../../08-endpoints/user-profile/configure-end-up-protection-mode.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **System Directory Protection Mode**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
    * Value Name: `ProtectionMode`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce strict system directory permissions and Object Manager protections)

---

## Rationale
Privileged Access Workstations (PAWs) host the most sensitive administrative sessions in the enterprise, including Domain Admin, Enterprise Admin, and Tier 0 identity management credentials. Any unauthorized file placement, symbolic link manipulation, or DLL planting in `%SystemRoot%` or system object manager namespaces could allow an unprivileged attacker or rogue maintenance utility to compromise the entire workstation integrity, leading to identity store takeover.

### 1. Session Manager Architecture & Object Manager Protection
During operating system initialization, the Windows Session Manager (`smss.exe`) parses `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`:
* When `ProtectionMode` is set to `1`, `smss.exe` locks down security descriptors across `%SystemRoot%` (`C:\Windows`), `%SystemRoot%\System32`, and all subsystem execution paths.
* It enforces strict separation and access boundaries within the Windows Object Manager namespace (`\BaseNamedObjects`, `\KnownDlls`, `\RPC Control`).
* Setting `ProtectionMode = 1` prevents standard accounts or compromised low-integrity worker processes from creating symlinks, hardlinks, or junction points that bridge into protected operating system structures.
* In a PAW architecture, where administrative scripts frequently invoke background management agents, rigid DACLs guarantee that no external binary or payload can be introduced into the system execution path.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Preventing Administrative DLL Planting**: Management tools executed by domain administrators search `%SystemRoot%\System32` before secondary paths. Enforcing `ProtectionMode = 1` eliminates any scenario where unprivileged users could manipulate directory permissions to plant malicious DLLs.
* **Thwarting Privileged Service Coercion**: Exploits targeting system services (such as Print Spooler, Diagnostics Hub, or installer services) often utilize file system junctions to redirect privileged file creations into system directories. Directory Protection Mode terminates these redirection vectors at the kernel namespace boundary.
* **Integrity Validation for PAW Workflows**: PAW configurations enforce clean, immutable directory trees. `ProtectionMode = 1` complements Windows Defender Application Control (WDAC) and AppLocker by providing foundational filesystem-level defense-in-depth.

### 3. MITRE ATT&CK Mapping
* **T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking**: Planting unauthorized dynamic modules in system directories.
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading**: Sideloading malicious dynamic libraries into trusted administration paths.
* **T1068 - Exploitation for Privilege Escalation**: Escalating local privileges via filesystem and object manager permission flaws.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs do not run legacy software, third-party productivity suites, or unverified developer utilities. All native Windows administration tools and RSAT modules fully comply with strict `%SystemRoot%` protections.
* **Zero Operational Disruption**: Enforcing `ProtectionMode = 1` produces zero negative operational impact on dedicated PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager`
   * **Value Name**: `ProtectionMode`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.
6. Note: Enforcing `ProtectionMode` requires a computer restart to apply to the Session Manager during initial boot.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Directory Protection Mode on the PAW console:

[Download Script: Configure-PawAuditProtectionmode.ps1](../implementation_scripts/Configure-PawAuditProtectionmode.ps1)

```powershell
# Configure-PawAuditProtectionmode.ps1
Write-Host "Enforcing System Mitigation control: protection-mode..." -ForegroundColor Cyan

# Set Registry value: ProtectionMode
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord -Force
Write-Host "    Enforced ProtectionMode = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditProtectionmodeStatus.ps1](../audit_scripts/Get-PawAuditProtectionmodeStatus.ps1)

```powershell
# Get-PawAuditProtectionmodeStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: ProtectionMode
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.ProtectionMode -ne 1) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000090, Windows 11 STIG Rule WN11-CC-000090
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and directory object permissions)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
