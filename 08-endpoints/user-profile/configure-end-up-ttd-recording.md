# [REQ-END-157] User Profile: Time-Travel Debugging (TTD) Recording Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-146](../../07-paws/user-profile/configure-paw-up-ttd-recording.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Time-Travel Debugging Recording Policy**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SOFTWARE\Microsoft\TTD`
    * Value Name: `RecordingPolicy`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Disabled / Prohibit Time-Travel Debugging recording system-wide)

---

## Rationale
Time-Travel Debugging (TTD) is an advanced diagnostic framework embedded in Microsoft development and troubleshooting tooling (such as WinDbg Preview and Windows Diagnostic Infrastructure). TTD works by recording a complete, instruction-by-instruction execution history of a process into a high-fidelity trace file (`.run`), which can then be replayed forwards and backwards in time. In an enterprise environment, unconstrained TTD recording represents a severe data exfiltration and credential theft vulnerability.

### 1. TTD Engine Architecture & Process Tracing Mechanics
When TTD records a target process:
* The TTD engine injects dynamic tracing hooks (`ttd.dll` and emulator shims) into the process virtual address space.
* It captures every thread context, CPU register state, memory read/write operation, and dynamic function call throughout the recording session.
* The generated `.run` trace file contains a complete snapshot of all process memory over time, including sensitive in-memory assets such as decrypted tokens, session cookies, plaintext passwords entered into forms, and asymmetric cryptographic keys.
* If an attacker running as a local user or compromised service initiates TTD recording against interactive applications or background services, they can extract sensitive memory contents without triggering conventional LSASS dump alerts or invoking suspicious API calls like `MiniDumpWriteDump()`.

### 2. Preventing Covert Memory Scraping via RecordingPolicy
Setting `RecordingPolicy = 2` enforces a system-wide restriction within the Windows TTD framework:
* **Value 0**: Default / User-configurable.
* **Value 1**: Enabled / Allow recording.
* **Value 2**: Disabled / Strictly prohibit TTD trace recording across all user and system processes.
* When set to `2`, the operating system blocks the initialization of the TTD tracing engine, preventing users, background tasks, and diagnostic scripts from recording memory traces on production endpoints.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Capturing memory traces of authentication processes to extract credentials.
* **T1125 - Automated Collection: Execution Tracing**: Capturing detailed process execution history and application state covertly.
* **T1057 - Process Discovery**: Inspecting internal process mechanics and runtime structures.

---

## Legacy Impact & Compatibility
* **Production Workstations**: Production workstations and member servers do not require TTD tracing for standard operations. Disabling TTD produces zero impact on standard enterprise software, productivity applications, or Windows Update.
* **Developer and Diagnostic Workstations**: Software development workstations actively utilizing WinDbg TTD for application debugging can be placed in a dedicated, isolated development Organizational Unit with specific diagnostic exemptions.
* **Performance Impact**: Zero. Disabling TTD prevents the overhead associated with CPU instruction emulator recording.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\TTD`
   * **Value Name**: `RecordingPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `2`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Time-Travel Debugging recording:

[Download Script: Configure-EndAuditTtdrecording.ps1](../implementation_scripts/Configure-EndAuditTtdrecording.ps1)

```powershell
# Configure-EndAuditTtdrecording.ps1
Write-Host "Enforcing System Mitigation control: ttd-recording..." -ForegroundColor Cyan

# Set Registry value: RecordingPolicy
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\TTD")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -Value 2 -Type DWord -Force
Write-Host "    Enforced RecordingPolicy = 2" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditTtdrecordingStatus.ps1](../audit_scripts/Get-EndAuditTtdrecordingStatus.ps1)

```powershell
# Get-EndAuditTtdrecordingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: RecordingPolicy
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.RecordingPolicy -ne 2) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000110, Windows 11 STIG Rule WN11-CC-000110
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing diagnostic memory capture)
* **Microsoft WinDbg Documentation**: Time-Travel Debugging Overview and Enterprise Security Policies
