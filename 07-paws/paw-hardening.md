# Hardening Requirement: Privileged Access Workstation Hardening

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  * Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker
  * Computer Configuration\Policies\Administrative Templates\System\Device Guard
  * Computer Configuration\Policies\Administrative Templates\System\Credentials Delegation
  * HKLM\SYSTEM\CurrentControlSet\Control\Lsa

---

## Rationale
Privileged Access Workstations (PAWs) provide a dedicated, isolated environment for sensitive tasks like Domain Controller administration. If an administrator uses a standard workstation (which is exposed to web browsing, emails, and third-party software) to perform domain administration, attackers can compromise the administrator's credentials via keystroke logging, memory dumping (LSASS), or session hijacking. 

Hardening the PAW operating system ensures:
1. **LSASS Protection**: Prevents in-memory credential harvesting via Credential Guard and LSA Protection.
2. **Execution Control**: AppLocker prevents the execution of unauthorized binaries, scripts, or installer packages.
3. **Data Protection**: BitLocker with TPM and pre-boot Startup PIN ensures the disk cannot be tampered with offline.
4. **Platform Integrity**: Device Guard (HVCI) uses virtualization-based security to ensure only trusted, signed drivers and code run in kernel mode.

---

## Legacy Impact & Compatibility
* **Daily Work Restriction**: Administrators cannot perform daily administrative tasks (e.g., checking email, accessing the internet, running productivity suites like Microsoft Office) on a PAW. They must use a secondary, standard workstation for these tasks.
* **Administrative Rights**: No standard domain users or lower-tier administrators may log on to the PAW. Local administrative rights are strictly disabled for domain accounts.
* **Hardware Requirements**: PAWs must have physical TPM 2.0 chips and support Virtualization-Based Security (VBS) in the UEFI/firmware.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Enable Credential Guard and Device Guard (HVCI)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the PAWs Organizational Unit (OU) (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Device Guard`
4. Configure the setting:
   * **Policy**: `Turn On Virtualization Based Security`
   * **Setting**: `Enabled`
   * **Select Platform Security Level**: `Secure Boot and DMA Protection`
   * **Virtualization Based Protection of Code Integrity**: `Enabled with UEFI lock`
   * **Credential Guard Configuration**: `Enabled with UEFI lock`

#### 2. Configure Strict AppLocker Rules
1. In the same GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
2. Right-click **Executable Rules** and select **Create Default Rules** (this permits Windows files and program files).
3. Delete the default rule allowing "Everyone" to run files in all locations, and replace it with a rule allowing only authorized administrative groups (e.g., `Tier0-Admins`) to run binaries outside the default system locations.
4. Set AppLocker Enforcement:
   * Right-click **AppLocker** and select **Properties**.
   * On the **Enforcement** tab, check **Configured** under **Executable rules** and select **Enforce rules**.

#### 3. Enforce BitLocker Drive Encryption
To protect the PAW operating system drive from offline data tampering and physical theft, implement the dedicated, high-security BitLocker settings. This includes mandatory TPM + pre-boot Startup PIN, XTS-AES 256 encryption, disabling sleep states (S1-S3), Kernel DMA protection, and automatic recovery key rotation.

Refer to the detailed implementation guide:
**[Enable BitLocker for PAWs](enable-bitlocker.md)**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally on the PAW to enforce LSA Protection, enable AppLocker's dependency service, and verify group membership.

```powershell
# Configure-PAWLocalSettings.ps1
# Configures local registry keys and services required for PAW isolation.

Write-Host "--- Applying Local PAW Hardening Settings ---" -ForegroundColor Cyan

# 1. Enable LSA Protection (RunAsPPL = 1)
$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "[+] LSA Protection (RunAsPPL) enabled in registry." -ForegroundColor Green

# 2. Configure AppLocker Service (AppIDSvc) to start automatically
$AppLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppLockerService) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "[+] Application Identity Service (AppIDSvc) set to Automatic and started." -ForegroundColor Green
} else {
    Write-Warning "[-] Application Identity Service not found on this machine."
}

# 3. Enable Virtualization-Based Security (VBS) and Credential Guard in registry
$DeviceGuardPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
if (-not (Test-Path $DeviceGuardPath)) {
    New-Item -Path $DeviceGuardPath -Force | Out-Null
}
Set-ItemProperty -Path $DeviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord
Set-ItemProperty -Path $DeviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord # 3 = Secure Boot and DMA
Set-ItemProperty -Path $DeviceGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord # 1 = Enabled with UEFI Lock
Write-Host "[+] Device Guard and Credential Guard keys configured." -ForegroundColor Green

Write-Host "`nLocal PAW modifications complete. Please reboot to enforce VBS and LSA protection." -ForegroundColor Cyan
```

*To verify the local PAW security posture:*
```powershell
# Test-PAWSecurityPosture.ps1
# Audits the local PAW state for BitLocker, AppIDSvc, and Credential Guard registry settings.

Write-Host "--- Auditing PAW Security Posture ---" -ForegroundColor Cyan

# 1. Audit BitLocker on C:
$Blt = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($Blt) {
    $BltColor = if ($Blt.ProtectionStatus -eq "On") { "Green" } else { "Red" }
    Write-Host "    - BitLocker C: Protection Status: $($Blt.ProtectionStatus) | Encryption: $($Blt.VolumeStatus)" -ForegroundColor $BltColor
} else {
    Write-Host "    - BitLocker: Volume information could not be retrieved." -ForegroundColor Red
}

# 2. Audit AppLocker Service
$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
if ($AppIDSvc) {
    $AppLockerColor = if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") { "Green" } else { "Red" }
    Write-Host "    - AppLocker Service Status: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType)" -ForegroundColor $AppLockerColor
}

# 3. Audit Local Administrators Group
$LocalAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
Write-Host "`n[+] Current Local Administrators (Must only contain local/authorized admin accounts):" -ForegroundColor Yellow
if ($LocalAdmins) {
    foreach ($Member in $LocalAdmins) {
        # Check if the member is a domain account (contains domain prefix or SID matches domain structure)
        $MemberColor = if ($Member.ObjectClass -eq "User" -and $Member.PrincipalSource -eq "Local") { "Green" } else { "Yellow" }
        Write-Host "    - Account: $($Member.Name) | Source: $($Member.PrincipalSource) | Class: $($Member.ObjectClass)" -ForegroundColor $MemberColor
    }
} else {
    Write-Warning "    - Local administrators group membership could not be retrieved."
}
```

---

## 🔗 Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R58 (Use of Privileged Access Workstations)
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.2.1 (LSA Protection), Section 18.8 (Device Guard/HVCI)
* **Microsoft Security Baselines**: Virtualization-Based Security (VBS) and Device Guard deployment guides.
