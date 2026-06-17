# [REQ-PAW-018] Enable Kernel-Mode Hardware-Enforced Stack Protection for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 11 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security -> Set **Kernel-level shadow stacks** to **Enabled**
  * **Registry Location**: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks
    * `Enabled` = `1` (REG_DWORD)

---

## Rationale
Kernel-mode Hardware-enforced Stack Protection uses CPU hardware features to protect the operating system kernel from memory corruption exploits, specifically Return-Oriented Programming (ROP) attacks.

On highly critical endpoints such as Privileged Access Workstations (PAWs), attackers aim to achieve kernel-mode execution to subvert administrative separation controls, bypass Endpoint Detection and Response (EDR) software, and extract domain credential secrets from isolated zones.

Intel Control-flow Enforcement Technology (CET) and AMD Shadow Stack technologies create a separate, hardware-secured copy of the call stack (the "shadow stack"). Before returning from a function, the CPU compares the return address on the standard stack with the address stored on the hardware-secured shadow stack. If a mismatch is detected, the processor terminates the thread or crashes the system, neutralizing control-flow hijacking attempts.

Deploying Kernel-mode Hardware-enforced Stack Protection on PAWs guarantees that the administrative gateway machines remain resilient against advanced kernel exploits.

---

## Legacy Impact & Compatibility
* **Hardware Requirements**: Systems must support hardware shadow stacks. This requires Intel 11th Gen Core (Tiger Lake) or newer processors, or AMD Zen 3 (Ryzen 5000) or newer processors.
* **Firmware & OS Requirements**: The system must run Windows 11 version 22H2 or newer. Additionally, the system must use UEFI BIOS with Secure Boot enabled.
* **Dependencies**: Virtualization-Based Security (VBS) and Hypervisor-Enforced Code Integrity (HVCI / Memory Integrity) must be enabled and active.
* **Driver Compatibility**: This feature enforces strict rules on kernel-mode code. Older, legacy, or improperly signed drivers—often associated with kernel-level anti-cheat software, legacy hardware, or debugging tools—will fail to load or may trigger system crashes (BSOD). PAW hardware should be carefully standardized on modern platforms to prevent driver compatibility issues.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the appropriate PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security` -> Set to **Enabled**
   * Check **Kernel-level shadow stacks** -> Set to **Enabled** (or set registry `Enabled` = `1`)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the registry and activate Kernel-mode Hardware-enforced Stack Protection.

[Download Script: Enable-PawKernelShadowStacks.ps1](implementation_scripts/Enable-PawKernelShadowStacks.ps1)

```powershell
# Enable-PawKernelShadowStacks.ps1
# Description: Configures HKLM registry to enable Kernel-mode Hardware-enforced Stack Protection (Kernel Shadow Stacks) for PAWs.

Write-Host "Enabling Kernel-mode Hardware-enforced Stack Protection for PAWs..." -ForegroundColor Cyan

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name "Enabled" -Value 1 -Type DWord
Write-Host "[+] Registry setting for PAW Kernel Shadow Stacks enabled. (Reboot required)." -ForegroundColor Green
```

*To audit the state of Kernel-mode Hardware-enforced Stack Protection:*

[Download Script: Test-PawKernelShadowStacks.ps1](audit_scripts/Test-PawKernelShadowStacks.ps1)

```powershell
# Test-PawKernelShadowStacks.ps1
# Description: Audits the registry status of Kernel-mode Hardware-enforced Stack Protection (Kernel Shadow Stacks) for PAWs.

Write-Host "--- Auditing PAW Kernel-mode Hardware-enforced Stack Protection ---" -ForegroundColor Cyan

$script:Vulnerable = $false
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks"

# Check registry value
$val = Get-ItemProperty -Path $RegPath -Name "Enabled" -ErrorAction SilentlyContinue
$actual = if ($val) { $val.Enabled } else { "" }

if ($actual -eq 1) {
    Write-Host "    - Registry Setting: KernelShadowStacks Enabled | Actual: '1' (Expected: '1')" -ForegroundColor Green
} else {
    $script:Vulnerable = $true
    Write-Host "    - Registry Setting: KernelShadowStacks Enabled | Actual: '$actual' (Expected: '1')" -ForegroundColor Red
}

# Verify VBS dependency is met
try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    if ($DG.VirtualizationBasedSecurityStatus -eq 2) {
        Write-Host "    - VBS Status: Running" -ForegroundColor Green
    } else {
        $script:Vulnerable = $true
        Write-Host "    - VBS Status: Not Running (VBS is required for Kernel Shadow Stacks)" -ForegroundColor Red
    }
} catch {
    $script:Vulnerable = $true
    Write-Host "    - DeviceGuard WMI class query failed. VBS is likely disabled." -ForegroundColor Red
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **Microsoft Windows Security Baselines**: Core Isolation Security Baseline
* **ANSSI AD Hardening Guide**: Section on hardware virtualization and kernel exploitation mitigation
* **DoD Windows 11 Computer STIG**: Device Guard / Virtualization-Based Security policies
