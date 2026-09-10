# [REQ-PAW-123] User Profile: Explorer Security and Memory Protections for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-134](../../08-endpoints/user-profile/configure-up-explorer-security.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Enforce Data Execution Prevention (DEP) for Explorer**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\File Explorer\Turn off Data Execution Prevention for Explorer` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer`
    * Value Name: `NoDataExecutionPrevention`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Keep DEP strictly enforced in Explorer)
  * **Enforce Heap Termination on Corruption for Explorer**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\File Explorer\Turn off heap termination on corruption` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer`
    * Value Name: `NoHeapTerminationOnCorruption`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Terminate Explorer immediately upon heap corruption)
  * **Shell Protocol Protected Mode**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\File Explorer\Shell Protocol Protected Mode` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
    * Value Name: `PreXPSP2ShellProtocolBehavior`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Restrict shell protocol handler to protected mode)

---

## Rationale
On Privileged Access Workstations (PAWs), File Explorer (`explorer.exe`) provides the interactive desktop shell within which all Tier 0 administrative tasks, credential entry, and management utilities operate. If an adversary or malicious script can exploit a memory corruption vulnerability within the Explorer process, they can execute arbitrary shellcode within the interactive administrative desktop station, compromising Kerberos tickets, session tokens, and Active Directory management sessions.

### 1. Memory Safety Internals inside Explorer.exe
File Explorer continuously hosts dynamic components, COM servers, file icon handlers, and system management namespace extensions:
* **Data Execution Prevention (`NoDataExecutionPrevention = 0`)**: Hardens memory pages by marking stack and heap allocations with the No-Execute (NX) CPU page table attribute. Any attempt by an exploit to divert CPU instruction flow into data buffers triggers an immediate hardware exception, neutralizing buffer overflow payloads.
* **Heap Termination on Corruption (`NoHeapTerminationOnCorruption = 0`)**: Commands the Windows user-mode heap manager to immediately terminate the process upon detecting any corruption in heap block headers or metadata. This fail-closed posture prevents attackers from weaponizing heap corruption (e.g., use-after-free or heap overflow) to achieve arbitrary code execution.
* **Shell Protocol Protected Mode (`PreXPSP2ShellProtocolBehavior = 0`)**: Enforces URL security zone validation on all `shell:` protocol invocations, preventing external scripts or document links from launching administrative binaries or scripts without security zone inspection.

### 2. Tier 0 Architectural Purity & Exploit Neutralization
* **Fail-Closed Security Posture**: On a PAW console, any process anomaly or corruption must result in instant process termination rather than allowing code to execute in an unstable or manipulated state.
* **Guarding Administrative Shell Extensions**: PAWs run administrative MMC snap-ins and management tools that register shell components. Enforcing DEP and heap termination protects Explorer from vulnerabilities in these administrative helper DLLs.
* **Synergy with Hardware Protections**: Complements kernel-level mitigations, Control Flow Guard (CFG), and Microsoft Defender Exploit Protection.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Exploiting vulnerabilities in Explorer shell extensions or preview handlers on administrative consoles.
* **T1546.015 - Event Triggered Execution: Component Object Model and Shell Extensions**: Exploiting COM shell extensions on PAWs.
* **T1055 - Process Injection**: Attempting memory corruption and shellcode injection into the desktop shell.
* **T1218 - System Binary Proxy Execution**: Proxying execution via legacy shell protocol handlers.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Administrative consoles exclusively run certified, modern Microsoft administrative tools and RSAT utilities. All supported tooling fully complies with DEP and heap termination standards.
* **Zero Operational Disruption**: Legitimate Active Directory administration, PowerShell scripting, and MMC consoles function with complete stability.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer`
4. Configure the following policies:
   * **Turn off Data Execution Prevention for Explorer**: Set to **Disabled**
   * **Turn off heap termination on corruption**: Set to **Disabled**
   * **Shell Protocol Protected Mode**: Set to **Enabled**
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Explorer security and memory protections on the PAW console:

[Download Script: Configure-PawUpexplorersecurity.ps1](../implementation_scripts/Configure-PawUpexplorersecurity.ps1)

```powershell
# Configure-PawUpexplorersecurity.ps1
Write-Host "Applying User Profile restriction: explorer-security..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-PawUpexplorersecurityStatus.ps1](../audit_scripts/Get-PawUpexplorersecurityStatus.ps1)

```powershell
# Get-PawUpexplorersecurityStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0"

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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x (File Explorer); CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000170, Windows 11 STIG Rule WN11-CC-000170
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and memory exploit defenses)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
