# [REQ-PAW-143] User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-154](../../08-endpoints/user-profile/configure-end-up-speculative-mitigations.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are dedicated exclusively to managing Tier 0 directory assets, where sensitive Kerberos TGTs, domain administrator password hashes, and enterprise PKI keys are processed in volatile memory. Speculative execution side-channel vulnerabilities (Spectre, Meltdown, MDS) allow unprivileged local code or sandboxed scripts to circumvent hardware security boundaries, leaking confidential kernel memory across address spaces.

### 1. CPU Speculative Execution & Side-Channel Mechanics
Modern microprocessors incorporate speculative out-of-order execution pipelines to maintain high performance. However, these architectural optimizations introduce side channels:
* **Branch Target Injection (Spectre Variant 2 / CVE-2017-5715)**: Adversaries manipulate CPU indirect branch predictors to coerce privileged code into executing speculatively, leaving cached footprints of sensitive memory contents.
* **Rogue Data Cache Load (Meltdown / CVE-2017-5754)**: Allows user-mode execution threads to speculatively read arbitrary supervisor (kernel) memory addresses before the MMU hardware privilege check aborts the operation.
* Through high-resolution cache timing techniques (such as `Flush+Reload`), an adversary reconstructs cryptographic keys and privileged tokens from CPU cache latency differences.
* On a PAW console, any leakage of kernel-space memory directly exposes LSASS structures, administrative Kerberos credentials, and domain management tokens.

### 2. Kernel Memory Manager Mitigations (KVAS & IBRS) on PAWs
Windows enforces strict isolation between user and supervisor contexts through CPU microcode and kernel paging:
* **Kernel Virtual Address Shadowing (KVAS)**: Completely unmaps kernel address space while user-mode threads are executing, ensuring that speculative data cache loads encounter unmapped memory rather than supervisor data structures.
* **Indirect Branch Restricted Speculation (IBRS) & Retpoline**: Restricts branch target speculation across execution modes, preventing cross-privilege branch poisoning.
* Setting `FeatureSettingsOverrideMask = 3` and `FeatureSettingsOverride = 72` (0x00000048) mandates that `ntoskrnl.exe` unconditionally activates both Meltdown and Spectre mitigations, ensuring maximum microarchitectural isolation for Tier 0 sessions.

### 3. MITRE ATT&CK Mapping
* **T1592.004 - Gather Victim Host Information: Client Configurations**: Profiling hardware and CPU vulnerabilities to execute side-channel attacks.
* **T1068 - Exploitation for Privilege Escalation**: Leveraging microarchitectural transient execution flaws to breach the kernel isolation boundary.
* **T1003 - OS Credential Dumping**: Reconstructing authentication hashes and private keys leaked through CPU cache side channels.

---

## Legacy Impact & Compatibility
* **Dedicated Hardware Profiles**: PAWs are deployed on modern enterprise-grade workstation hardware equipped with modern Intel Core vPro / Xeon or AMD Ryzen Pro processors featuring silicon-level hardware mitigations. Performance degradation on modern hardware is negligible.
* **Microcode Verification**: Ensure PAW endpoint firmware (UEFI BIOS) is updated to the latest manufacturer release to deliver required processor microcode updates.
* **Zero Operational Disruption**: Tier 0 administrative workflows, RSAT, and PowerShell operate seamlessly under enforced speculative execution mitigations.

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
6. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.
7. Note: A computer restart is required for the Windows kernel to initialize speculative CPU execution mitigations.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce speculative execution mitigations on the PAW console:

[Download Script: Configure-PawAuditSpeculativemitigations.ps1](../implementation_scripts/Configure-PawAuditSpeculativemitigations.ps1)

```powershell
# Configure-PawAuditSpeculativemitigations.ps1
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

[Download Script: Get-PawAuditSpeculativemitigationsStatus.ps1](../audit_scripts/Get-PawAuditSpeculativemitigationsStatus.ps1)

```powershell
# Get-PawAuditSpeculativemitigationsStatus.ps1
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
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
