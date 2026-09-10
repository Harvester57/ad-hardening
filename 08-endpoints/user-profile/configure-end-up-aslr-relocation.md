# [REQ-END-153] User Profile: Address Space Layout Randomization (ASLR) Image Relocation for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-142](../../07-paws/user-profile/configure-paw-up-aslr-relocation.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Address Space Layout Randomization (ASLR) is a foundational defense against memory corruption vulnerabilities. By randomizing the memory locations of program headers, code segments, stacks, heaps, and libraries, ASLR ensures that an adversary cannot reliably predict target memory addresses when attempting to hijack execution flow.

### 1. Memory Manager Internals & PE Base Relocation
By default, the Windows memory manager only randomizes binaries compiled with the `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` (`/DYNAMICBASE`) linker flag:
* Legacy or unhardened third-party Portable Executable (PE) binaries compiled without `/DYNAMICBASE` request a static preferred base address (such as `0x00400000` for 32-bit executables or `0x140000000` for 64-bit binaries).
* When a non-ASLR module is loaded at a predictable virtual address, its executable code pages contain static machine instructions that adversaries utilize to construct Return-Oriented Programming (ROP) or Jump-Oriented Programming (JOP) chains.
* These ROP chains stitch together small machine instructions ("gadgets") ending in `RET` instructions to call Windows API functions like `VirtualProtect()` or `VirtualAlloc()`, flipping memory permissions from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE` and completely neutralizing Data Execution Prevention (DEP/NX).
* Setting `MoveImages = 4294967295` (0xFFFFFFFF) instructs the Windows kernel memory manager (`ntoskrnl.exe`) to force relocation on every module loaded into process address spaces, stripping adversaries of fixed ROP gadget pivots.

### 2. Threat Vectors & Exploitation Mechanics
* **Neutralizing ROP Gadget Catalogs**: Attackers scanning client workstations for unhardened helper DLLs or legacy plugins cannot rely on static gadget addresses, causing memory corruption exploits to trigger immediate access violations and process crashes rather than code execution.
* **Defense-in-Depth Beyond Exploit Protection XML**: While Windows Defender Exploit Protection allows configuring Mandatory ASLR on a per-binary basis via XML, setting the system-wide kernel parameter `MoveImages` ensures unconditional coverage across all newly installed applications, background services, and third-party tools without requiring manual XML profile updates.
* **Mitigating Client-Side Exploits**: Web browsers, document viewers, and email clients frequently load diverse third-party extensions. Mandatory ASLR forces bottom-up and top-down randomization across all loaded dependencies.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Exploiting vulnerabilities in client applications through memory corruption payloads.
* **T1055 - Process Injection**: Injecting code into target process address spaces using memory manipulation techniques.
* **T1068 - Exploitation for Privilege Escalation**: Weaponizing memory corruption flaws to elevate privileges within the operating system.

---

## Legacy Impact & Compatibility
* **Pre-Requisite PE Relocation Tables**: Modules that lack a relocation table (`.reloc` section) and were not compiled with `/DYNAMICBASE` cannot be relocated dynamically. If such a legacy application attempts to load, the operating system may refuse to load the binary or fail during initialization.
* **Legacy Line-of-Business Applications**: Obsolete enterprise applications compiled prior to Visual Studio 2005 / GCC 4.x that stripped relocation tables may require vendor upgrades or application-specific Exploit Protection overrides.
* **Performance Impact**: Negligible. Modern x64 processors and memory management units (MMUs) incur zero measurable latency during base address relocation.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
   * **Value Name**: `MoveImages`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `4294967295` (Decimal) or `0xFFFFFFFF` (Hexadecimal)
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.
6. Note: Enforcing `MoveImages` requires a computer restart to apply to core operating system kernel processes.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce system-wide ASLR image relocation:

[Download Script: Configure-EndAuditAslrrelocation.ps1](../implementation_scripts/Configure-EndAuditAslrrelocation.ps1)

```powershell
# Configure-EndAuditAslrrelocation.ps1
Write-Host "Enforcing System Mitigation control: aslr-relocation..." -ForegroundColor Cyan

# Set Registry value: MoveImages
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 4294967295 -Type DWord -Force
Write-Host "    Enforced MoveImages = 4294967295" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditAslrrelocationStatus.ps1](../audit_scripts/Get-EndAuditAslrrelocationStatus.ps1)

```powershell
# Get-EndAuditAslrrelocationStatus.ps1
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
* **Microsoft Security Guidance**: Exploit Protection Reference - Mandatory ASLR and Bottom-Up Randomization
