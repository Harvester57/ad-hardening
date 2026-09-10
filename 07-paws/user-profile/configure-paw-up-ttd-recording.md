# [REQ-PAW-146] User Profile: Time-Travel Debugging (TTD) Recording Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-157](../../08-endpoints/user-profile/configure-end-up-ttd-recording.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) process the highest-value authentication secrets in the enterprise, including Kerberos Ticket Granting Tickets (TGTs), domain administrator password hashes, and directory replication metadata. Time-Travel Debugging (TTD) records complete CPU instruction sequences and process memory states into persistent `.run` trace files. If left unconstrained on a PAW, an adversary could weaponize TTD to harvest Tier 0 credentials without triggering traditional LSASS access alerts.

### 1. TTD Engine Architecture & Credential Exfiltration
The Microsoft Time-Travel Debugging engine provides low-level instruction tracing for Windows applications:
* When TTD attaches to a target process, it records all register states, memory pages, thread interactions, and API parameters into an indexed binary log.
* If weaponized against an administrative console, TTD captures plaintext credentials entered into administrative management utilities, Kerberos session tickets decrypted in memory, and sensitive Active Directory database queries.
* Unlike traditional debugger attachments or memory dumps via `MiniDumpWriteDump`, TTD operates via instruction-level emulation hooks, presenting an evasive mechanism for credential dumping that can bypass legacy EDR heuristics.
* The resulting `.run` file contains full forensic data that could be exfiltrated to compromise the entire Active Directory domain.

### 2. Strict Prohibition on PAW Consoles
Setting `RecordingPolicy = 2` disables the TTD recording infrastructure at the system level:
* The operating system refuses to initialize TTD tracing hooks in any process context on the PAW.
* This setting enforces the core architectural principle that Tier 0 consoles must not contain developer or diagnostic recording tools that expose execution state.
* It complements Credential Guard, LSA Protected Process Light (PPL), and WDAC by closing down low-level diagnostic tracing channels.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**: Capturing memory traces of authentication processes to extract credentials.
* **T1125 - Automated Collection: Execution Tracing**: Capturing detailed process execution history and application state covertly.
* **T1057 - Process Discovery**: Inspecting internal process mechanics and runtime structures.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Development and debugging tools (Visual Studio, WinDbg, SDKs) are strictly prohibited on PAWs by design. Disabling TTD aligns with administrative console isolation guidelines.
* **Zero Operational Disruption**: Core administrative utilities, RSAT, and PowerShell 5.1/7.x operate without any dependency on TTD.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\TTD`
   * **Value Name**: `RecordingPolicy`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `2`
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable Time-Travel Debugging recording on the PAW console:

[Download Script: Configure-PawAuditTtdrecording.ps1](../implementation_scripts/Configure-PawAuditTtdrecording.ps1)

```powershell
# Configure-PawAuditTtdrecording.ps1
Write-Host "Enforcing System Mitigation control: ttd-recording..." -ForegroundColor Cyan

# Set Registry value: RecordingPolicy
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\TTD")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -Value 2 -Type DWord -Force
Write-Host "    Enforced RecordingPolicy = 2" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditTtdrecordingStatus.ps1](../audit_scripts/Get-PawAuditTtdrecordingStatus.ps1)

```powershell
# Get-PawAuditTtdrecordingStatus.ps1
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
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
