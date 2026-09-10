# [REQ-PAW-142] User Profile: Address Space Layout Randomization (ASLR) Image Relocation for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-153](../../08-endpoints/user-profile/configure-end-up-aslr-relocation.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Mandatory ASLR Image Relocation (MoveImages)**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
    * Value Name: `MoveImages`
    * Value Type: `REG_DWORD`
    * Value Data: `4294967295` (0xFFFFFFFF / Mandatory ASLR system-wide)

---

## Rationale
Privileged Access Workstations (PAWs) host high-integrity administrative tooling, PowerShell sessions, and directory management utilities where memory safety is critical to preventing credential harvesting. Mandatory Address Space Layout Randomization (ASLR) image relocation enforces systematic randomization across all executable binaries and loaded DLLs, depriving adversaries of static memory targets for Return-Oriented Programming (ROP) exploitation.

### 1. Memory Manager Internals & ROP Neutralization
In administrative environments, threat actors attempt to achieve code execution or privilege escalation by exploiting memory corruption vulnerabilities in administrative processes:
* Executable modules compiled without the `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`/DYNAMICBASE`) flag request a fixed virtual memory base address upon invocation.
* Fixed memory bases provide predictable locations for executable machine instruction snippets ("gadgets"). In a Return-Oriented Programming (ROP) exploit, an attacker chains these gadgets together to execute privileged Windows API calls (such as `VirtualProtect` or `WriteProcessMemory`) without needing to inject unbacked executable code.
* Setting `MoveImages = 4294967295` (0xFFFFFFFF) forces the Windows NT kernel memory manager (`ntoskrnl.exe`) to randomize the base address of all loaded PE images during virtual address allocation, completely invalidating pre-calculated ROP gadget chains.

### 2. Tier 0 Threat Vectors & PAW Isolation
* **Protecting Privileged Administrative Tooling**: PAW operators utilize administrative tools such as Active Directory Administrative Center, PowerShell, RSAT, and custom management modules. Forcing system-wide ASLR guarantees that even legacy management snap-ins or third-party administration libraries cannot be exploited as fixed-address gadget reservoirs.
* **Depriving Exploit Payloads of Predictable Targets**: Any memory corruption attempt targeting a randomized binary causes an unhandled access violation (`EXCEPTION_ACCESS_VIOLATION` / `0xC0000005`), terminating the offending process and triggering an immediate Windows Defender / Event Log crash alert rather than yielding control to an attacker.
* **Synergy with Hardware-Enforced Stack Protection (CET)**: Combined with Control Flow Guard (CFG) and Intel CET / AMD Shadow Stack, Mandatory ASLR provides a multi-layered defense that stops advanced memory corruption exploits at the hardware and kernel boundaries.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Exploiting vulnerabilities in administrative processes to gain unauthorized execution.
* **T1055 - Process Injection**: Attempting process injection via memory address tampering in administrative contexts.
* **T1068 - Exploitation for Privilege Escalation**: Escalating privileges through memory corruption vulnerabilities on dedicated administration consoles.

---

## Legacy Impact & Compatibility
* **Dedicated Administrative Environment**: Because PAWs run exclusively modern, curated administrative applications and RSAT tools, all supported binaries are compiled with relocation tables. Disabling fixed base loading causes zero operational disruption on dedicated PAW consoles.
* **Unsupported Legacy Software**: Legacy, 16-bit, or unhardened non-relocatable software suites are strictly prohibited on PAWs by design.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
   * **Value Name**: `MoveImages`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `4294967295` (Decimal) or `0xFFFFFFFF` (Hexadecimal)
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.
6. Note: Enforcing `MoveImages` requires a computer restart to apply to core operating system kernel processes.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce system-wide ASLR image relocation on the PAW console:

[Download Script: Configure-PawAuditAslrrelocation.ps1](../implementation_scripts/Configure-PawAuditAslrrelocation.ps1)

```powershell
# Configure-PawAuditAslrrelocation.ps1
Write-Host "Enforcing System Mitigation control: aslr-relocation..." -ForegroundColor Cyan

# Set Registry value: MoveImages
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 4294967295 -Type DWord -Force
Write-Host "    Enforced MoveImages = 4294967295" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditAslrrelocationStatus.ps1](../audit_scripts/Get-PawAuditAslrrelocationStatus.ps1)

```powershell
# Get-PawAuditAslrrelocationStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: MoveImages
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.MoveImages -ne 4294967295) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000080, Windows 11 STIG Rule WN11-CC-000080
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Application and kernel exploit mitigation baselines)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
