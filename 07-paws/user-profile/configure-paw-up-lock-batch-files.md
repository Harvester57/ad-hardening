# [REQ-PAW-145] User Profile: Command Processor Batch File Locking for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-156](../../08-endpoints/user-profile/configure-end-up-lock-batch-files.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Command Processor Batch File Locking**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Command Processor`
    * Value Name: `LockBatchFilesWhenInUse`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce mandatory file locking on active batch scripts)

---

## Rationale
Privileged Access Workstations (PAWs) are dedicated exclusively to directory administration, identity synchronization, and domain-level maintenance. Administrative batch scripts running on PAWs often operate in high-integrity or `SYSTEM` contexts to orchestrate directory backups, certificate rollover tasks, or network diagnostics. Allowing concurrent processes to modify active scripts creates a critical privilege escalation vector.

### 1. Command Processor Streaming Internals & TOCTOU Vulnerability
The legacy Windows Command Processor (`cmd.exe`) does not load an entire script into memory upon execution:
* It reads instructions iteratively from disk, processing lines sequentially and seeking file pointers dynamically.
* By default, `cmd.exe` opens batch files with shared write access (`FILE_SHARE_WRITE`), enabling any process running under an authorized identity or low-integrity context to rewrite the file contents during execution.
* An attacker with local access or malware executing concurrently can inject commands into the active batch file. When `cmd.exe` reads the next block from disk, it executes the injected commands within the administrative execution context.
* On a PAW console, where administrative scripts handle sensitive directory objects and authentication tokens, dynamic script tampering directly compromises Tier 0 administrative credentials.

### 2. File Locking Enforcement on PAW Consoles
Setting `LockBatchFilesWhenInUse = 1` enforces strict file locking semantics across all instances of `cmd.exe`:
* The Command Processor opens batch files with exclusive read sharing (`FILE_SHARE_READ`), completely disallowing write or delete access from other processes.
* Any concurrent write attempt returns `ERROR_SHARING_VIOLATION` (`0x20`), preventing on-the-fly script tampering.
* This setting complements PowerShell Constrained Language Mode and Windows Defender Application Control (WDAC) by closing an inherent file-locking loophole in the legacy command shell.

### 3. MITRE ATT&CK Mapping
* **T1059.003 - Command and Scripting Interpreter: Windows Command Shell**: Executing commands through cmd.exe batch scripts.
* **T1565.001 - Data Manipulation: Stored Data Manipulation**: Modifying batch files on disk during execution to hijack program control flow.
* **T1068 - Exploitation for Privilege Escalation**: Weaponizing race conditions in administrative scripts to achieve arbitrary code execution under elevated identities.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Modern administrative workflows on PAWs rely almost exclusively on PowerShell rather than legacy batch files. Any existing batch utilities adhere to standard programming practices and do not modify themselves during execution.
* **Zero Operational Disruption**: Enforcing `LockBatchFilesWhenInUse = 1` causes zero disruption to standard PAW management workflows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Command Processor`
   * **Value Name**: `LockBatchFilesWhenInUse`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Command Processor batch file locking on the PAW console:

[Download Script: Configure-PawAuditLockbatchfiles.ps1](../implementation_scripts/Configure-PawAuditLockbatchfiles.ps1)

```powershell
# Configure-PawAuditLockbatchfiles.ps1
Write-Host "Enforcing System Mitigation control: lock-batch-files..." -ForegroundColor Cyan

# Set Registry value: LockBatchFilesWhenInUse
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Command Processor")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -Value 1 -Type DWord -Force
Write-Host "    Enforced LockBatchFilesWhenInUse = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditLockbatchfilesStatus.ps1](../audit_scripts/Get-PawAuditLockbatchfilesStatus.ps1)

```powershell
# Get-PawAuditLockbatchfilesStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LockBatchFilesWhenInUse
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LockBatchFilesWhenInUse -ne 1) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000105, Windows 11 STIG Rule WN11-CC-000105
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and script execution environments)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
