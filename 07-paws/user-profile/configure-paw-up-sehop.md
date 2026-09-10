# [REQ-PAW-140] User Profile: Structured Exception Handling Overwrite Protection (SEHOP) for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-151](../../08-endpoints/user-profile/configure-end-up-sehop.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **SEHOP Chain Validation Enforcement**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel`
    * Value Name: `DisableExceptionChainValidation`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Enforces SEH exception chain validation system-wide)

---

## Rationale
Dedicated Privileged Access Workstations (PAWs) are the cornerstone of Tier 0 infrastructure security. While PAWs predominantly run native 64-bit administrative consoles, administrative utilities, MMC snap-ins, or legacy automation tools may invoke 32-bit processes under WOW64. Enforcing Structured Exception Handling Overwrite Protection (SEHOP) system-wide prevents stack corruption exploits from subverting the exception handling mechanism on high-privilege management stations.

### 1. SEH Internals & Stack Corruption Mechanics
On 32-bit x86 processes and WOW64 emulation layers, Structured Exception Handling (SEH) registers handlers on the execution thread's stack:
* A linked list of `EXCEPTION_REGISTRATION_RECORD` structs stores the address of exception callback routines.
* In memory exploitation techniques targeting buffer overflows, adversaries deliberately overwrite these stack-based records with shellcode pointers or ROP gadget vectors.
* When an exception occurs or is forced, the dispatcher transfers control directly to the attacker-supplied handler, executing code in the context of the running administrative process.
* On a PAW, where administrative processes interact directly with Domain Controller RPC interfaces and LSA secrets, any successful execution flow hijack poses catastrophic risk to the entire Active Directory forest.

### 2. SEHOP Validation Algorithm & Protection Boundary
SEHOP intercepts the exception dispatch flow inside `ntdll.dll` before any exception handler executes:
* **Integrity Traversal**: The dispatcher verifies that every `Next` pointer in the chain resides within the valid thread stack boundary defined by `TEB->NtTib.StackBase` and `TEB->NtTib.StackLimit`.
* **System Anchor Validation**: It confirms that the final link in the chain points to `ntdll!FinalExceptionHandler`. If an attacker overwrites a record or redirects a pointer to unmapped/heap space, the anchor verification fails.
* **Fail-Closed Execution Model**: The kernel instantly terminates the application (`STATUS_INVALID_EXCEPTION_HANDLER` / `0xC00001A5`), denying the attacker an execution pivot.
* Setting `DisableExceptionChainValidation = 0` guarantees that SEHOP protection is unconditionally enforced across all processes running on the PAW console.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Weaponizing stack overflows and SEH overwrites on administrative workstations.
* **T1055 - Process Injection**: Hijacking thread execution context through corrupted exception frames.
* **T1068 - Exploitation for Privilege Escalation**: Gaining elevated execution rights via memory corruption in management tools.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Modern administrative tools for Windows Server (Active Directory Administrative Center, RSAT, PowerShell) are fully 64-bit and natively utilize table-based exception handling. Any 32-bit utilities permitted on PAWs adhere strictly to Microsoft standard compiler standards.
* **Zero Disruption**: Enabling SEHOP produces zero operational impact on certified PAW environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager\kernel`
   * **Value Name**: `DisableExceptionChainValidation`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
5. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.
6. Note: Enforcing `DisableExceptionChainValidation` requires a system restart to take effect on the kernel exception dispatcher.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce SEHOP exception chain validation on the PAW console:

[Download Script: Configure-PawAuditSehop.ps1](../implementation_scripts/Configure-PawAuditSehop.ps1)

```powershell
# Configure-PawAuditSehop.ps1
Write-Host "Enforcing System Mitigation control: sehop..." -ForegroundColor Cyan

# Set Registry value: DisableExceptionChainValidation
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force
Write-Host "    Enforced DisableExceptionChainValidation = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-PawAuditSehopStatus.ps1](../audit_scripts/Get-PawAuditSehopStatus.ps1)

```powershell
# Get-PawAuditSehopStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: DisableExceptionChainValidation
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.DisableExceptionChainValidation -ne 0) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000085, Windows 11 STIG Rule WN11-CC-000085
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Application and kernel exploit mitigation baselines)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
