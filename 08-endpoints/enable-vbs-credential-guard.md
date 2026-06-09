# Hardening Requirement: Enable VBS and Credential Guard

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\System\Device Guard\Turn On Virtualization Based Security
  * HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard

---

## Rationale
Virtualization-Based Security (VBS) uses hardware virtualization features to create and isolate a secure region of memory from the normal operating system. 

Windows Defender **Credential Guard** runs inside this isolated VBS environment (known as the secure kernel). By moving NTLM password hashes, Kerberos Ticket Granting Tickets (TGTs), and other domain credentials into this virtualized container, Credential Guard ensures they are inaccessible to the standard operating system. 

If VBS and Credential Guard are not enabled:
1. **LSASS Access**: Attackers running with administrative rights on the workstation can query the LSASS process memory space and extract Active Directory authentication tokens using memory-dumping tools (e.g., Mimikatz).
2. **Pass-the-Hash / Pass-the-Ticket**: Attackers can use the extracted hashes or Kerberos tickets to log on to other domain systems, leading to rapid lateral movement and domain compromise.

Enforcing VBS and Credential Guard prevents in-memory credential harvesting, breaking the primary lateral movement escalation vector.

---

## Legacy Impact & Compatibility
* **Virtualization Conflicts**: Third-party virtualization software (such as legacy versions of VMware Workstation or VirtualBox) that do not support nested virtualization or integration with Windows Hyper-V will fail to run when VBS is active.
* **Hardware Requirements**: Systems must support CPU virtualization (Intel VT-x or AMD-V), Second Level Address Translation (SLAT), and have secure firmware (UEFI, Secure Boot, IOMMU / DMA protection). Older client hardware that does not support these specifications cannot run Credential Guard.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security`
   * **Setting**: `Enabled`
   * **Select Platform Security Level**: `Secure Boot and DMA Protection`
   * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
   * **Credential Guard Configuration**: `Enabled with UEFI lock`

*Note: The "Enabled with UEFI lock" setting ensures that an administrator cannot remotely disable Credential Guard via registry changes alone; it requires physical access to the machine to clear UEFI variables on reboot.*

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure registry keys to enable VBS and Credential Guard.

```powershell
# Enable-VBSCredentialGuard.ps1
# Configures local registry keys to activate VBS and Credential Guard.

Write-Host "--- Enforcing VBS & Credential Guard ---" -ForegroundColor Cyan

$DeviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"

if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}

# Enable Virtualization-Based Security (VBS)
Set-ItemProperty -Path $DeviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
# RequirePlatformSecurityFeatures = 3 (Secure Boot and DMA Protection)
Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord
# HypervisorEnforcedCodeIntegrity = 1 (HVCI / Memory Integrity Enabled)
Set-ItemProperty -Path $DeviceGuardPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1 -Type DWord
# LsaCfgFlags = 1 (Credential Guard Enabled with UEFI Lock)
Set-ItemProperty -Path $DeviceGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord

Write-Host "[+] VBS and Credential Guard registry settings applied. (Reboot required)." -ForegroundColor Green
```

*To audit VBS and Credential Guard status using WMI:*
```powershell
# Test-VBSCredentialGuard.ps1
# Queries the local Win32_DeviceGuard class to verify active protection states.

Write-Host "--- Auditing Virtualization-Based Security Baseline ---" -ForegroundColor Cyan

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
} catch {
    Write-Host "    - VULNERABLE: DeviceGuard WMI class could not be queried. VBS is likely disabled." -ForegroundColor Red
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.8.14.1 (Turn On Virtualization Based Security), Section 18.8.14.2 (Turn On Virtualization Based Security: Credential Guard Configuration)
* **ANSSI AD Hardening Guide**: Recommendations regarding LSA Protection and Credential Guard deployment.
