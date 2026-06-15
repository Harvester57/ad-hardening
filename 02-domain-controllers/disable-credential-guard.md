# [REQ-DC-007] Disable Credential Guard

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Device Guard`
  * **Policy**: `Turn On Virtualization-Based Security`
  * **Setting**: `Enabled`
    * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
    * **Credential Guard Configuration**: `Disabled`
    * **Require UEFI Memory Attributes Table**: `Enabled`
    * **Secure Launch Configuration**: `Enabled`
    * **Select Platform Security Level**: `Secure Boot`
  * **Registry Location (VBS)**: `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` for:
    * `EnableVirtualizationBasedSecurity` = `1` (REG_DWORD)
    * `HVCIMATRequired` = `1` (REG_DWORD)
    * `ConfigureSystemGuardLaunch` = `1` (REG_DWORD)
    * `RequirePlatformSecurityFeatures` = `1` (REG_DWORD)
    * `HypervisorEnforcedCodeIntegrity` = `1` (REG_DWORD)
  * **Registry Location (Credential Guard)**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` -> `LsaCfgFlags` = `0` (REG_DWORD)

---

## Rationale
Virtualization-Based Security (VBS) and Hypervisor-Protected Code Integrity (HVCI) should be enabled on Domain Controllers to protect the integrity of the operating system kernel and enforce driver blocklists.

However, Windows Defender Credential Guard must **not** be deployed on Active Directory domain controllers. Credential Guard is designed to isolate LSA secrets to prevent credential-dumping tools from harvesting password hashes from local memory. Domain controllers do not store user credentials in LSASS memory in the same way member servers do; instead, credentials are stored securely in the Active Directory database (ntds.dit). Furthermore, domain controllers run LSASS in a manner that requires active cryptographic operations and delegation capabilities that are incompatible with the restrictions imposed by Credential Guard.

Enabling Credential Guard on a domain controller can lead to authentication failures, block Kerberos delegation features, and cause operational instability without providing any security benefits.

For official warnings and product specifications, refer to the Microsoft documentation:
[Microsoft Security Guidance: Windows Defender Credential Guard Warnings](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

---

## Legacy Impact & Compatibility
* **Virtualization-Based Security**: Enabling VBS and Memory Integrity (HVCI) requires compliant virtualization hardware (Secure Boot, SLAT, IOMMU). Ensure hypervisors and host environments are fully compatible prior to deployment.
* **Domain Controller Functionality**: Disabling Credential Guard on domain controllers is the standard, officially supported Microsoft configuration. It ensures that critical Active Directory services, authentication protocols, and delegation features operate without restriction or compatibility failures.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Device Guard`
4. Set the following policy:
   * **Policy**: `Turn On Virtualization-Based Security`
   * **Setting**: `Enabled`
   * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
   * **Credential Guard Configuration**: `Disabled`
   * **Require UEFI Memory Attributes Table**: `Enabled`
   * **Secure Launch Configuration**: `Enabled`
   * **Select Platform Security Level**: `Secure Boot`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the settings locally.

[Download Script: Configure-DisableCredentialGuard.ps1](implementation_scripts/Configure-DisableCredentialGuard.ps1)

```powershell
# Configure-DisableCredentialGuard.ps1
# Description: Enables Virtualization-Based Security (VBS) and disables Credential Guard in the registry.

Write-Host "Applying hardening requirement: Enable VBS Baseline and Disable Credential Guard..." -ForegroundColor Cyan

# 1. Enable Virtualization-Based Security and related hypervisor options
$vbsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $vbsPath)) {
    New-Item -Path $vbsPath -Force | Out-Null
}

$vbsSettings = @{
    "EnableVirtualizationBasedSecurity" = 1
    "HVCIMATRequired"                   = 1
    "ConfigureSystemGuardLaunch"        = 1
    "RequirePlatformSecurityFeatures"   = 1
    "HypervisorEnforcedCodeIntegrity"   = 1
}

foreach ($Setting in $vbsSettings.Keys) {
    Set-ItemProperty -Path $vbsPath -Name $Setting -Value $vbsSettings[$Setting] -Type DWord -ErrorAction Stop
}
Write-Host "Virtualization-Based Security parameters enabled in registry." -ForegroundColor Green

# 2. Disable Credential Guard (LsaCfgFlags: 0 = Disabled)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $lsaPath)) {
    New-Item -Path $lsaPath -Force | Out-Null
}
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 0 -Type DWord
Write-Host "Credential Guard configured to Disabled in registry." -ForegroundColor Green

Write-Host "Hardening applied successfully. A system reboot is required." -ForegroundColor Green
```

*To audit VBS and Credential Guard status using Registry and WMI:*

[Download Script: Get-CredentialGuardStatus.ps1](audit_scripts/Get-CredentialGuardStatus.ps1)

```powershell
# Get-CredentialGuardStatus.ps1
# Description: Audits the configuration and operational status of VBS and ensures Credential Guard is disabled.

Write-Host "--- Auditing VBS and Credential Guard Status ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit Registry Settings
$vbsRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$lsaReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -ErrorAction SilentlyContinue

$ExpectedVbsSettings = @{
    "EnableVirtualizationBasedSecurity" = 1
    "HVCIMATRequired"                   = 1
    "ConfigureSystemGuardLaunch"        = 1
    "RequirePlatformSecurityFeatures"   = 1
    "HypervisorEnforcedCodeIntegrity"   = 1
}

if (Test-Path $vbsRegPath) {
    $vbsValues = Get-ItemProperty -Path $vbsRegPath -ErrorAction SilentlyContinue
    foreach ($Setting in $ExpectedVbsSettings.Keys) {
        $Val = $vbsValues.$Setting
        $Expected = $ExpectedVbsSettings[$Setting]
        if ($Val -eq $Expected) {
            Write-Host "[+] VBS setting '$Setting' is correctly configured ($Val)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: VBS setting '$Setting' is missing or incorrect ($Val)." -ForegroundColor Red
            $vulnerable = $true
        }
    }
} else {
    Write-Host "[!] VULNERABLE: Virtualization-Based Security registry path does not exist." -ForegroundColor Red
    $vulnerable = $true
}

# For DCs, Credential Guard (LsaCfgFlags) must be set to 0 (Disabled)
if ($null -ne $lsaReg -and $lsaReg.LsaCfgFlags -ne 0) {
    Write-Host "[!] VULNERABLE: Credential Guard is enabled in registry (LsaCfgFlags = $($lsaReg.LsaCfgFlags))." -ForegroundColor Red
    $vulnerable = $true
} else {
    $val = if ($null -eq $lsaReg) { "Not configured (Disabled)" } else { $lsaReg.LsaCfgFlags }
    Write-Host "[+] Credential Guard registry key 'LsaCfgFlags' is correctly set to disabled ($val)." -ForegroundColor Green
}

# 2. Audit WMI Operational State (if running)
$deviceGuard = Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    # SecurityServicesRunning: 1 = Credential Guard
    $servicesRunning = $deviceGuard.SecurityServicesRunning
    $cgRunning = $false
    foreach ($service in $servicesRunning) {
        if ($service -eq 1) { $cgRunning = $true }
    }
    
    if ($cgRunning) {
        Write-Host "[!] VULNERABLE: Credential Guard is running operationally on this Domain Controller." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] Credential Guard is not running on this Domain Controller." -ForegroundColor Green
    }
} else {
    Write-Host "[-] WMI class Win32_DeviceGuard is not available." -ForegroundColor Yellow
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE (Credential Guard enabled or VBS misconfigured)" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE (Credential Guard disabled and VBS configured)" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **Microsoft Security Guidance**: [Windows Defender Credential Guard Warnings and Exclusions](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)
* **ANSSI AD Hardening Guide**: Recommendation R14 (acknowledging that Credential Guard is excluded from Domain Controllers due to compatibility constraints, while LSA protection remains active)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.31.2 (noting that Credential Guard is restricted to compatible systems and excludes Active Directory Domain Controllers)
