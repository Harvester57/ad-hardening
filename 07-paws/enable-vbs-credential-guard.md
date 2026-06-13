# [REQ-PAW-010] Enable VBS and Credential Guard for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: Computer Configuration\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security
  * **Registry Location**: HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
    * `EnableVirtualizationBasedSecurity` = `1` (REG_DWORD)
    * `RequirePlatformSecurityFeatures` = `1` (REG_DWORD, Secure Boot)
    * `HypervisorEnforcedCodeIntegrity` = `1` (REG_DWORD)
    * `LsaCfgFlags` = `1` (REG_DWORD, Credential Guard Enabled with UEFI Lock)
    * `ConfigureSystemGuardLaunch` = `1` (REG_DWORD, Secure Launch Enabled)
    * `HVCIMATRequired` = `1` (REG_DWORD, Require UEFI Memory Attributes Table)

---

## Rationale
Privileged Access Workstations (PAWs) contain Tier 0 administrative tokens. A compromise of a PAW leads to a direct compromise of the Active Directory database (NTDS.dit) and full domain domain control. Mitigating credential dumping is the single most critical security objective for a PAW.

1. **Virtualization-Based Security (VBS)**: VBS establishes an isolated, secure kernel space using hypervisor hardware virtualization. This secure kernel is separated from the host operating system, preventing root-level exploits from accessing virtualized memory blocks.
2. **Credential Guard**: Running within the VBS secure kernel, Credential Guard stores credential secrets (NTLM hashes, Kerberos TGTs) inside an isolated memory container. By shifting these secrets outside the standard Local Security Authority (LSA) process memory space, it blocks credential-dumping utilities (like Mimikatz) from harvesting secrets from memory.
3. **Secure Launch**: System Guard Secure Launch protects firmware boot integrity by using hardware-enforced boot measurements. It isolates the hypervisor startup from potential rootkits or boot-level malware.
4. **UEFI Memory Attributes Table (MAT)**: Enforcing UEFI MAT ensures that the bootloader validates page permissions in firmware, preventing buffer overflow or execution redirection vulnerabilities in pre-boot configurations.

---

## Legacy Impact & Compatibility
* **Firmware Requirements**: PAWs must use modern UEFI firmware, native UEFI boot (Legacy CSM disabled), Secure Boot, IOMMU (Intel VT-d or AMD-Vi), CPU Virtualization (Intel VT-x or AMD-V), and TPM 2.0. Enabling Secure Boot and virtualization functions is a strict pre-requisite. Refer to [REQ-PAW-005 - UEFI Firmware Security Hardening](configure-uefi-security.md) and [REQ-PAW-006 - Enable Hardware Virtualization and DMA Protection](enable-hardware-virtualization-and-dma-protection.md) to secure these features in the firmware. If physical hardware does not meet these criteria, it is unfit for use as a PAW.
* **Hypervisor Conflicts**: Standard Windows virtualization layers will be required. Running non-compliant third-party hypervisors (such as older VirtualBox or VMware Workstation configurations) that do not support nested virtualization on Hyper-V will fail.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security`
   * **Setting**: `Enabled`
   * **Select Platform Security Level**: `Secure Boot`
   * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
   * **Credential Guard Configuration**: `Enabled with UEFI lock`
   * **Secure Launch Configuration**: `Enabled`
   * **Require UEFI Memory Attributes Table**: `Enabled`
5. Link the GPO to the PAWs Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the local registry parameters to activate VBS, Credential Guard, and Secure Launch.

[Download Script: Enable-PawVBSCredentialGuard.ps1](implementation_scripts/Enable-PawVBSCredentialGuard.ps1)

```powershell
# Enable-PawVBSCredentialGuard.ps1
# Description: Configures local registry keys to activate VBS and Credential Guard on PAWs.

Write-Host "--- Enforcing VBS & Credential Guard for PAWs ---" -ForegroundColor Cyan

$DeviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

# Enable Virtualization-Based Security (VBS)
Set-ItemProperty -Path $DeviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
# RequirePlatformSecurityFeatures = 1 (Secure Boot)
Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord
# HypervisorEnforcedCodeIntegrity = 1 (HVCI / Memory Integrity Enabled)
Set-ItemProperty -Path $DeviceGuardPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord
# LsaCfgFlags = 1 (Credential Guard Enabled with UEFI Lock)
Set-ItemProperty -Path $DeviceGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord
# ConfigureSystemGuardLaunch = 1 (Secure Launch Enabled)
Set-ItemProperty -Path $DeviceGuardPath -Name "ConfigureSystemGuardLaunch" -Value 1 -Type DWord
# HVCIMATRequired = 1 (Require UEFI Memory Attributes Table)
Set-ItemProperty -Path $DeviceGuardPath -Name "HVCIMATRequired" -Value 1 -Type DWord

Write-Host "[+] PAW VBS and Credential Guard registry settings applied. (Reboot required)." -ForegroundColor Green
```

*To audit VBS and Credential Guard status using WMI and Registry:*
[Download Script: Test-PawVBSCredentialGuard.ps1](audit_scripts/Test-PawVBSCredentialGuard.ps1)

```powershell
# Test-PawVBSCredentialGuard.ps1
# Description: Queries the local Win32_DeviceGuard class and registry settings to verify VBS protection states on PAWs.

Write-Host "--- Auditing PAW Virtualization-Based Security Baseline ---" -ForegroundColor Cyan

try {
    $DG = Get-CimInstance -Namespace "Root\Microsoft\Windows\DeviceGuard" -ClassName "Win32_DeviceGuard" -ErrorAction Stop
    
    # SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI
    $CredGuardRunning = $DG.SecurityServicesRunning -contains 1
    $HvciRunning = $DG.SecurityServicesRunning -contains 2
    
    $VbsColor = if ($DG.VirtualizationBasedSecurityStatus -eq 2) { "Green" } else { "Red" }
    $CredColor = if ($CredGuardRunning) { "Green" } else { "Red" }
    $HvciColor = if ($HvciRunning) { "Green" } else { "Red" }
    
    Write-Host "    - VBS Status: $($DG.VirtualizationBasedSecurityStatus) (Required = 2 [Running])" -ForegroundColor $VbsColor
    Write-Host "    - Credential Guard Running: $CredGuardRunning (Required = True)" -ForegroundColor $CredColor
    Write-Host "    - Hypervisor Code Integrity Running: $HvciRunning (Required = True)" -ForegroundColor $HvciColor
    
    # Query registry properties for System Guard and UEFI MAT
    $SystemGuard = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureSystemGuardLaunch" -ErrorAction SilentlyContinue).ConfigureSystemGuardLaunch
    $MatRequired = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "HVCIMATRequired" -ErrorAction SilentlyContinue).HVCIMATRequired
    
    $SgColor = if ($SystemGuard -eq 1) { "Green" } else { "Red" }
    $MatColor = if ($MatRequired -eq 1) { "Green" } else { "Red" }
    
    Write-Host "    - System Guard Secure Launch: $SystemGuard (Required = 1)" -ForegroundColor $SgColor
    Write-Host "    - UEFI Memory Attributes Table Required: $MatRequired (Required = 1)" -ForegroundColor $MatColor
} catch {
    Write-Host "    - VULNERABLE: DeviceGuard WMI class could not be queried. VBS is likely disabled." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.8.14.1 (Turn On Virtualization Based Security), Section 18.8.14.2 (Turn On Virtualization Based Security: Credential Guard Configuration)
* **ANSSI AD Hardening Guide**: Recommendations regarding administrative workstation isolation and credential protections.
