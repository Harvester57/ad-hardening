# [REQ-END-154] User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-143](../../07-paws/user-profile/configure-paw-up-speculative-mitigations.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Speculative Execution Feature Settings Override**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
    * Value Name: `FeatureSettingsOverride`
    * Value Type: `REG_DWORD`
    * Value Data: `72` (0x00000048 / Enforces hardware-assisted branch prediction mitigations)
  * **Speculative Execution Feature Settings Override Mask**:
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
    * Value Name: `FeatureSettingsOverrideMask`
    * Value Type: `REG_DWORD`
    * Value Data: `3` (0x00000003 / Enforces Spectre Variant 2 and Meltdown KVAS coverage)

---

## Rationale
Transient execution vulnerabilities (such as Spectre, Meltdown, Foreshadow/L1TF, and Microarchitectural Data Sampling / MDS) break architectural isolation boundaries by exploiting CPU speculative execution and out-of-order execution optimizations. Hardware cache side-channel attacks allow unprivileged user-mode processes to reconstruct secret memory contents from kernel address space and adjacent processes.

### 1. CPU Speculative Execution & Side-Channel Mechanics
Modern microprocessors execute instructions speculatively beyond unresolved conditional branches to maximize pipeline throughput:
* When branch prediction guesses incorrectly, the CPU rolls back architectural register state, but changes made to microarchitectural state—specifically the L1, L2, and L3 CPU data caches—remain intact.
* **Meltdown (CVE-2017-5754 / Rogue Data Cache Load)**: Exploits out-of-order execution to read supervisor-only (kernel) memory from user space before the CPU hardware permission check completes.
* **Spectre Variant 2 (CVE-2017-5715 / Branch Target Injection)**: An attacker trains the CPU Indirect Branch Predictor (IBP) to mispredict indirect branch destinations, coercing privileged kernel code into speculatively executing attacker-chosen gadget instructions that leak secret data into the CPU cache.
* By performing cache timing measurements (such as `Flush+Reload` or `Prime+Probe`), an unprivileged attacker measures differences in memory access latency to deduce the values of kernel secrets, cryptographic keys, and user tokens bit-by-bit.

### 2. Kernel Memory Manager Mitigations (KVAS & IBRS)
Windows provides kernel-level software mitigations coupled with CPU microcode features to isolate execution boundaries:
* **Kernel Virtual Address Shadowing (KVAS / KPTI)**: Completely separates user-mode page tables from kernel-mode page tables. While executing in user mode, the kernel address space is completely unmapped from the virtual address table, preventing Meltdown-class transient memory reads.
* **Indirect Branch Restricted Speculation (IBRS) & Retpoline**: Restricts indirect branch speculation across privilege boundaries, ensuring that unprivileged code cannot poison branch predictors used by the kernel or hypervisor.
* **Registry Bitmask Architecture**:
  * Setting `FeatureSettingsOverrideMask = 3` (Bits 0 and 1) tells `ntoskrnl.exe` to take control of both Spectre Variant 2 (`0x1`) and Meltdown (`0x2`) mitigation flags.
  * Setting `FeatureSettingsOverride = 72` (`0x00000048`: Bit 3 for Speculative Store Bypass Disable / SSBD, and Bit 6 for L1TF) ensures comprehensive side-channel protection across all CPU cores.

### 3. MITRE ATT&CK Mapping
* **T1592.004 - Gather Victim Host Information: Client Configurations**: Profiling hardware and CPU vulnerabilities to execute side-channel attacks.
* **T1068 - Exploitation for Privilege Escalation**: Leveraging microarchitectural transient execution flaws to breach the kernel isolation boundary.
* **T1003 - OS Credential Dumping**: Reconstructing authentication hashes and private keys leaked through CPU cache side channels.

---

## Legacy Impact & Compatibility
* **Performance Considerations**: Enabling speculative execution mitigations introduces variable CPU performance overhead depending on the hardware processor generation. Systems utilizing modern Intel 10th Gen+ or AMD Zen 2+ processors with hardware-native in-silicon mitigations experience minimal performance impact (< 1-2%). Legacy processors relying heavily on software page-table flipping (KVAS) may incur higher CPU overhead on I/O-intensive workloads.
* **Firmware / Microcode Pre-Requisites**: Hardware CPU microcode updates provided via OEM BIOS updates or Windows Update cumulative packages are required to enable full IBRS/IBPB hardware support.
* **Virtualization Compatibility**: Hyper-V, VMware vSphere, and Citrix virtual machines require hypervisor-level CPU feature masking and updated virtual hardware versions to expose speculative mitigation MSRs to guest operating systems.

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
   * **Value Name**: `FeatureSettingsOverride`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `72`
5. Create a second Registry Item:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management`
   * **Value Name**: `FeatureSettingsOverrideMask`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `3`
6. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.
7. Note: A computer restart is required for the Windows kernel to initialize speculative CPU execution mitigations.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce speculative execution mitigations:

[Download Script: Configure-EndAuditSpeculativemitigations.ps1](../implementation_scripts/Configure-EndAuditSpeculativemitigations.ps1)

```powershell
# Configure-EndAuditSpeculativemitigations.ps1
Write-Host "Enforcing System Mitigation control: speculative-mitigations..." -ForegroundColor Cyan

# Set Registry value: FeatureSettingsOverride
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 72 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverride = 72" -ForegroundColor Green

# Set Registry value: FeatureSettingsOverrideMask
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverrideMask = 3" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditSpeculativemitigationsStatus.ps1](../audit_scripts/Get-EndAuditSpeculativemitigationsStatus.ps1)

```powershell
# Get-EndAuditSpeculativemitigationsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: FeatureSettingsOverride
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverride -ne 72) {
    $script:Vulnerable = $true
}

# Audit Registry value: FeatureSettingsOverrideMask
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverrideMask -ne 3) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000095, Windows 11 STIG Rule WN11-CC-000095
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Hardware and CPU speculative execution mitigations)
* **Microsoft Security Advisory**: ADV180002 (Guidance to mitigate speculative execution side-channel vulnerabilities)
