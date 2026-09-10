# [REQ-END-151] User Profile: Structured Exception Handling Overwrite Protection (SEHOP) for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-140](../../07-paws/user-profile/configure-paw-up-sehop.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
Structured Exception Handling (SEH) is a core Win32 application mechanism designed to manage runtime hardware and software exceptions. However, 32-bit Win32 and WOW64 processes maintain SEH records directly on the thread's stack, creating a classic attack vector for stack buffer overflows where adversaries hijack exception dispatching to execute arbitrary shellcode.

### 1. SEH Internals & Stack Corruption Mechanics
On 32-bit Windows architectures and 64-bit systems executing 32-bit binaries via WOW64, the operating system tracks active exception handlers using a singly-linked list of `EXCEPTION_REGISTRATION_RECORD` structures located on the thread stack:
* Each record contains two 32-bit pointers: `Next` (pointing to the subsequent registration record further down the stack) and `Handler` (pointing to the exception filter callback function).
* The head of the list is referenced directly by the Thread Environment Block (`TEB->NtTib.ExceptionList`).
* In an unmitigated environment, a stack buffer overflow allows an attacker to overwrite local variables, stack canaries (/GS cookies), and the adjacent `EXCEPTION_REGISTRATION_RECORD`.
* The attacker replaces the `Handler` address with a pointer to shellcode or a `POP-POP-RET` ROP gadget, and triggers a fault (e.g., dereferencing an invalid memory address). When the Windows exception dispatcher (`ntdll!RtlDispatchException`) processes the fault, it transfers control directly to the attacker-controlled address.

### 2. SEHOP Validation Algorithm
Structured Exception Handling Overwrite Protection (SEHOP) validates the structural integrity of the entire SEH linked list before the operating system dispatches any exception:
* **Chain Walk Verification**: `RtlDispatchException` traverses the linked list from the TEB to ensure that all `Next` pointers point higher on the thread stack and fall within valid stack limits (`StackBase` and `StackLimit`).
* **Final Handler Confirmation**: SEHOP confirms that the linked list terminates cleanly at the operating system's well-known terminal handler (`ntdll!FinalExceptionHandler`). If an attacker overwrote intermediate pointers, the terminal handler is unreachable.
* **Instant Process Termination**: If any validation check fails, the kernel identifies the corruption as an exploit attempt, immediately aborts process execution with status `STATUS_INVALID_EXCEPTION_HANDLER` (`0xC00001A5`), and logs a security event, preventing shellcode execution.
* Setting `DisableExceptionChainValidation = 0` guarantees that SEHOP is active across all processes system-wide.

### 3. MITRE ATT&CK Mapping
* **T1203 - Exploitation for Client Execution**: Weaponizing stack overflows and SEH overwrites in client applications.
* **T1055 - Process Injection**: Hijacking thread execution context through corrupted exception frames.
* **T1068 - Exploitation for Privilege Escalation**: Gaining elevated execution rights via memory corruption in background services.

---

## Legacy Impact & Compatibility
* **64-bit Native Binaries**: 64-bit Windows binaries (x64) utilize table-based exception handling recorded in the PE header's `.pdata` directory rather than stack-based SEH chains. Native 64-bit processes are unaffected by SEHOP.
* **32-bit and WOW64 Applications**: Legitimate 32-bit applications that adhere to standard Microsoft compiler conventions run with zero compatibility issues. Rare legacy applications utilizing custom, non-standard exception handling frameworks or unbacked in-memory code generators may encounter crashes and require modern vendor updates.
* **Performance Impact**: Negligible. The chain validation algorithm performs a small pointer-walking loop only when an exception is thrown, introducing virtually no CPU overhead during normal execution.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager\kernel`
   * **Value Name**: `DisableExceptionChainValidation`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `0`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.
6. Note: Enforcing `DisableExceptionChainValidation` requires a system restart to take effect on the kernel exception dispatcher.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce SEHOP exception chain validation:

[Download Script: Configure-EndAuditSehop.ps1](../implementation_scripts/Configure-EndAuditSehop.ps1)

```powershell
# Configure-EndAuditSehop.ps1
Write-Host "Enforcing System Mitigation control: sehop..." -ForegroundColor Cyan

# Set Registry value: DisableExceptionChainValidation
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force
Write-Host "    Enforced DisableExceptionChainValidation = 0" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditSehopStatus.ps1](../audit_scripts/Get-EndAuditSehopStatus.ps1)

```powershell
# Get-EndAuditSehopStatus.ps1
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
* **Microsoft Security Guidance**: Structured Exception Handling Overwrite Protection (SEHOP) Architectural Whitepaper
