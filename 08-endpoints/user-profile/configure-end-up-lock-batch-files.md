# [REQ-END-156] User Profile: Command Processor Batch File Locking for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-145](../../07-paws/user-profile/configure-paw-up-lock-batch-files.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Windows Command Processor (`cmd.exe`) is widely utilized for system administration, software installation routines, and scheduled maintenance tasks. By default, `cmd.exe` executes batch files (`.bat` and `.cmd`) using a streaming file read approach rather than caching the entire script in memory or acquiring a persistent file lock. This design exposes systems to Time-of-Check to Time-of-Use (TOCTOU) race conditions and dynamic script manipulation attacks.

### 1. Command Processor Streaming Internals & TOCTOU Vulnerability
When `cmd.exe` processes a batch file:
* It opens the target script, reads a single line or command block up to the current file pointer offset, executes the command, and closes or seeks the file handle for subsequent iterations.
* In default configurations, `cmd.exe` does not lock the file against write access (`FILE_SHARE_WRITE` remains permitted).
* An unprivileged adversary or malicious background process that possesses write access to the directory or file (such as scripts located in `%TEMP%`, `C:\ProgramData`, or shared network paths) can modify the script on disk while it is actively executing.
* When `cmd.exe` seeks forward to read subsequent lines, it executes the injected attacker commands in the security context of the user or privileged service running the script. If the batch script is executed by `SYSTEM` or an elevated administrator, the attacker immediately achieves Local Privilege Escalation (LPE).

### 2. File Locking Enforcement Mechanics
Setting `LockBatchFilesWhenInUse = 1` modifies the file-opening behavior of `cmd.exe`:
* When invoking a batch script, the Command Processor requests exclusive read sharing without write sharing (`FILE_SHARE_READ`), preventing any concurrent process from modifying, truncating, or appending to the script file until execution completes.
* Any attempt by an external process to write to or rename the active script results in an immediate sharing violation error (`ERROR_SHARING_VIOLATION` / `0x20`), neutralizing dynamic code hijacking attempts.
* This policy provides critical protection for automated enterprise deployment scripts, logon scripts, and software update wrappers.

### 3. MITRE ATT&CK Mapping
* **T1059.003 - Command and Scripting Interpreter: Windows Command Shell**: Executing malicious commands through cmd.exe batch scripting.
* **T1565.001 - Data Manipulation: Stored Data Manipulation**: Modifying batch files on disk during execution to hijack program control flow.
* **T1068 - Exploitation for Privilege Escalation**: Leveraging race conditions in batch file execution to execute code under elevated identities.

---

## Legacy Impact & Compatibility
* **Concurrent Self-Modifying Scripts**: Rare legacy administration scripts that deliberately append output or status logs to their own `.bat` file while running will fail due to sharing violations. Such scripts represent poor programming practice and must be refactored to write logs to external files (e.g., `%TEMP%\script.log`).
* **External Script Updaters**: Automated deployment tools that attempt to overwrite an active batch file while it is executing will be blocked until the script finishes. This is the intended secure behavior.
* **Operational Footprint**: Zero impact on standard application execution, PowerShell scripts, or compiled software.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\Command Processor`
   * **Value Name**: `LockBatchFilesWhenInUse`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Command Processor batch file locking:

[Download Script: Configure-EndAuditLockbatchfiles.ps1](../implementation_scripts/Configure-EndAuditLockbatchfiles.ps1)

```powershell
# Configure-EndAuditLockbatchfiles.ps1
Write-Host "Enforcing System Mitigation control: lock-batch-files..." -ForegroundColor Cyan

# Set Registry value: LockBatchFilesWhenInUse
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Command Processor")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -Value 1 -Type DWord -Force
Write-Host "    Enforced LockBatchFilesWhenInUse = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditLockbatchfilesStatus.ps1](../audit_scripts/Get-EndAuditLockbatchfilesStatus.ps1)

```powershell
# Get-EndAuditLockbatchfilesStatus.ps1
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
* **Microsoft Windows Command Processor Documentation**: Command Processor Execution Architecture and File Sharing Semantics
