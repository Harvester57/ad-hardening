# Hardening Requirement: Enable Credential Guard

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11 (Enterprise and Datacenter editions)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Device Guard`
  * **Policy**: `Turn On Virtualization-Based Security`
  * **Setting**: `Enabled`
    * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
    * **Credential Guard Configuration**: `Enabled with UEFI lock`
    * **Require UEFI Memory Attributes Table**: `Enabled`
    * **Secure Launch Configuration**: `Enabled`
    * **Select Platform Security Level**: `Secure Boot`
  * **Registry Location (VBS)**: `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` for:
    * `EnableVirtualizationBasedSecurity` = `1` (REG_DWORD)
    * `HVCIMATRequired` = `1` (REG_DWORD)
    * `ConfigureSystemGuardLaunch` = `1` (REG_DWORD)
    * `RequirePlatformSecurityFeatures` = `1` (REG_DWORD)
    * `HypervisorEnforcedCodeIntegrity` = `1` (REG_DWORD)
  * **Registry Location (Credential Guard)**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` -> `LsaCfgFlags` = `1` (REG_DWORD, Enabled with UEFI lock) or `2` (REG_DWORD, Enabled without UEFI lock)

---

## Rationale
Windows Defender Credential Guard uses virtualization-based security (VBS) to isolate secrets (such as NTLM password hashes and Kerberos Ticket Granting Tickets) in a secure, hypervisor-protected environment running parallel to the standard Windows kernel. 

By running LSA in a secure container separate from the main LSASS process, Credential Guard ensures that even if the host's operating system kernel is fully compromised by an administrative attacker (e.g., via kernel exploitation or driver execution), the attacker cannot retrieve plaintext secrets or NTLM password hashes from memory. This completely blocks common credential extraction techniques and tools.

---

## Legacy Impact & Compatibility
* **Hardware Requirements**: Enabling UEFI Secure Boot and CPU virtualization features is a strict pre-requisite for Credential Guard. For physical systems, refer to [UEFI Firmware Security Hardening](../07-paws/configure-uefi-security.md) and [Hardware Virtualization and DMA Protection](../07-paws/enable-hardware-virtualization-and-dma-protection.md) to secure these configurations.
* **Virtualization Support**: If the target server is a virtual machine, the hypervisor must support nested virtualization, and the virtual machine configuration must have VBS features enabled.
* **Authentication Protocol Impact**: Enabling Credential Guard disables NTLMv1, MS-CHAPv2, CredSSP single sign-on, and unconstrained Kerberos delegation. Applications that rely on these insecure delegation or authentication methods will fail.
* **Smart Card Requirement**: Kerberos authentication using smart cards is fully supported, but the smart card drivers must be compatible with VBS environment constraints.

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
   * **Credential Guard Configuration**: `Enabled with UEFI lock` (Note: UEFI lock prevents remote registry modification of these settings; use `Enabled without UEFI lock` if you require remote management capabilities to disable the control if needed).
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the settings locally.

[Download Script: Configure-CredentialGuard.ps1](implementation_scripts/Configure-CredentialGuard.ps1)

```powershell
# Configure-CredentialGuard.ps1
# Description: Enables Virtualization-Based Security (VBS) and Credential Guard in the registry.

Write-Host "Applying hardening requirement: Enable Credential Guard and VBS Baseline..." -ForegroundColor Cyan

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

# 2. Configure Credential Guard (LsaCfgFlags: 1 = UEFI Lock, 2 = No UEFI Lock)
$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $lsaPath)) {
    New-Item -Path $lsaPath -Force | Out-Null
}
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord
Write-Host "Credential Guard configured with UEFI lock in registry." -ForegroundColor Green

Write-Host "Hardening applied successfully. A system reboot is required." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-CredentialGuardStatus.ps1](audit_scripts/Get-CredentialGuardStatus.ps1)

```powershell
# Get-CredentialGuardStatus.ps1
# Description: Audits the configuration and operational status of Credential Guard.

Write-Host "--- Auditing Credential Guard ---" -ForegroundColor Cyan
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

if ($lsaReg -and ($lsaReg.LsaCfgFlags -eq 1 -or $lsaReg.LsaCfgFlags -eq 2)) {
    Write-Host "[+] Credential Guard registry key is configured (LsaCfgFlags = $($lsaReg.LsaCfgFlags))." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Credential Guard registry key 'LsaCfgFlags' is missing or set to 0." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit WMI Operational State (if running)
$deviceGuard = Get-CimInstance -Namespace "root\cimv2" -ClassName "Win32_DeviceGuard" -ErrorAction SilentlyContinue
if ($deviceGuard) {
    # SecurityServicesConfigured: 1 = Credential Guard
    $servicesConfigured = $deviceGuard.SecurityServicesConfigured
    # SecurityServicesRunning: 1 = Credential Guard
    $servicesRunning = $deviceGuard.SecurityServicesRunning
    
    $cgConfigured = $false
    $cgRunning = $false
    
    foreach ($service in $servicesConfigured) {
        if ($service -eq 1) { $cgConfigured = $true }
    }
    foreach ($service in $servicesRunning) {
        if ($service -eq 1) { $cgRunning = $true }
    }
    
    if ($cgConfigured) {
        Write-Host "[+] Credential Guard is configured operationally." -ForegroundColor Green
    } else {
        Write-Host "[-] Credential Guard is not configured in WMI (requires reboot/hardware compatibility)." -ForegroundColor Yellow
    }
    
    if ($cgRunning) {
        Write-Host "[+] Credential Guard is running." -ForegroundColor Green
    } else {
        Write-Host "[-] Credential Guard is not running in WMI (requires reboot/hardware compatibility)." -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] WMI class Win32_DeviceGuard is not available (common on older OS or without Hyper-V features installed)." -ForegroundColor Yellow
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE (Registry configurations missing)" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE (Registry configurations applied)" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R14 (LSA Protection and credential isolation defenses)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.31.2 (Ensure 'Turn On Virtualization-Based Security: Select Credential Guard Configuration' is set to 'Enabled with UEFI lock')
* **Microsoft Security Guidance**: Windows Defender Credential Guard requirements and deployment
