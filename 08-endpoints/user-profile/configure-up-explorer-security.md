# [REQ-END-134] User Profile: Explorer Security and Memory Protections

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-123](../../07-paws/user-profile/configure-up-explorer-security.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Windows File Explorer (`explorer.exe`) is the primary interactive user shell and file management environment in Windows. Because Explorer regularly parses untrusted file metadata, extracts icon caches, hosts third-party shell preview handlers, and processes custom URL protocol schemes, it represents a prime target for memory corruption exploits and arbitrary command execution.

### 1. Memory Safety Internals inside Explorer.exe
Windows Explorer loads numerous dynamically registered dynamic-link libraries, shell extensions, thumbnail generators, and preview handlers directly into its address space:
* **Data Execution Prevention (`NoDataExecutionPrevention = 0`)**: DEP marks data memory pages (such as the default process heap, user stacks, and memory pools) as non-executable (`PAGE_READWRITE` without `EXECUTE`). If a buffer overflow in a third-party thumbnail handler or shell extension attempts to execute code from a data page, the CPU memory management unit (MMU) generates an immediate hardware fault, terminating the process and stopping shellcode execution.
* **Heap Termination on Corruption (`NoHeapTerminationOnCorruption = 0`)**: The Windows user-mode heap manager incorporates integrity validation heuristics. When an application corrupts heap control structures (via heap buffer overflows, use-after-free conditions, or double-free flaws), setting this parameter ensures that `explorer.exe` terminates immediately (`STATUS_HEAP_CORRUPTION` / `0xC0000374`). Disabling heap termination allows the process to continue running with corrupted heap metadata, enabling attackers to perform heap spraying and control-flow hijacking.

### 2. Shell Protocol Protected Mode & URI Handler Hardening
* **Shell Protocol Handler (`PreXPSP2ShellProtocolBehavior = 0`)**: Windows registers custom URI protocol schemes, including the `shell:` protocol.
* In legacy, unhardened Windows configurations, web browsers, document viewers, or malicious shortcut files (`.lnk`) could invoke the `shell:` protocol handler to execute arbitrary executable files or script interpreters without security zone evaluation.
* Enforcing `PreXPSP2ShellProtocolBehavior = 0` restricts the `shell:` protocol to modern Protected Mode, enforcing strict URL security zone checks and blocking unauthorized command execution invoked via web links or Office documents.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Exploiting vulnerabilities in Explorer shell extensions or preview handlers.
* **T1546.015 - Event Triggered Execution: Component Object Model and Shell Extensions**: Weaponizing Explorer COM extensions for persistence and execution.
* **T1055 - Process Injection**: Attempting memory corruption and shellcode execution inside the Explorer desktop process.
* **T1218 - System Binary Proxy Execution**: Executing unauthorized local binaries via legacy shell protocol handlers.

---

## Legacy Impact & Compatibility
* **Legitimate Shell Extensions**: Modern shell extensions, context menu handlers, and preview handlers that comply with standard Microsoft Win32 development practices operate cleanly with DEP and heap termination enforced.
* **Buggy Third-Party Add-ins**: Poorly developed legacy third-party shell extensions with unpatched memory leaks or buffer overflows will crash Explorer rather than hanging the desktop or exposing the machine to exploitation. Faulty extensions should be updated by their respective vendors.
* **Operational Footprint**: Zero performance penalty; provides foundational platform resilience for all interactive users.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer`
4. Configure the following policies:
   * **Turn off Data Execution Prevention for Explorer**: Set to **Disabled**
   * **Turn off heap termination on corruption**: Set to **Disabled**
   * **Shell Protocol Protected Mode**: Set to **Enabled**
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Explorer security and memory protections:

[Download Script: Configure-Upexplorersecurity.ps1](../implementation_scripts/Configure-Upexplorersecurity.ps1)

```powershell
# Configure-Upexplorersecurity.ps1
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

[Download Script: Get-UpexplorersecurityStatus.ps1](../audit_scripts/Get-UpexplorersecurityStatus.ps1)

```powershell
# Get-UpexplorersecurityStatus.ps1
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
* **Microsoft Windows Shell Documentation**: File Explorer Process Architecture, DEP Enforcement, and Shell Protocol Protected Mode
