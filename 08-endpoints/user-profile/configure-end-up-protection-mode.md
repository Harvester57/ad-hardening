# [REQ-END-152] User Profile: Directory Protection Mode for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-141](../../07-paws/user-profile/configure-paw-up-protection-mode.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **System Directory Protection Mode**:
    * GPO Path: `Computer Configuration\Administrative Templates\System\Mitigations` (or Group Policy Preferences Registry Policy)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`
    * Value Name: `ProtectionMode`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Enforce strict system directory permissions and Object Manager protections)

---

## Rationale
Securing the Windows system root and core system directories against unauthorized modification is essential to preventing Local Privilege Escalation (LPE) and DLL planting attacks. The `ProtectionMode` registry setting configures the Windows Session Manager (`smss.exe`) to enforce hardened security descriptors across critical system directories and Object Manager namespaces during operating system initialization.

### 1. Session Manager Architecture & Object Manager Protection
During operating system bootstrap, the Windows Session Manager (`smss.exe`) reads `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`:
* When `ProtectionMode` is set to `1`, `smss.exe` enforces strict discretionary access control lists (DACLs) across `%SystemRoot%` (`C:\Windows`), `%SystemRoot%\System32`, and all dependent system subdirectories.
* It restricts the ability of unprivileged users to create symbolic links, directory junctions, or object links within protected system namespaces (such as `\BaseNamedObjects` and `\KnownDlls`).
* In default or legacy configurations where `ProtectionMode` is not explicitly enforced, certain legacy compatibility modes allow standard users to write temporary files or create object manager symlinks in system paths.
* Adversaries exploit these permissive DACLs by executing symbolic link redirection attacks, coercing privileged services (such as Windows Update, TrustedInstaller, or system diagnostic tasks) into overwriting protected binary files or writing malicious DLLs into system execution paths.

### 2. Threat Vectors & Exploitation Mechanics
* **DLL Search Order Hijacking**: Unprivileged malware cannot place rogue DLLs into `%SystemRoot%` or `%SystemRoot%\System32` where privileged services prioritize dynamic module resolution.
* **Symlink and Hardlink Escalation**: Setting `ProtectionMode = 1` prevents unprivileged users from manipulating object manager namespace links to redirect privileged file writes from non-privileged temporary directories to protected system files.
* **Tamper-Resistant Driver Directories**: Driver repositories (`%SystemRoot%\System32\drivers`) and system configurations are locked down, preventing unprivileged tampering with system service configurations.

### 3. MITRE ATT&CK Mapping
* **T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking**: Planting unauthorized DLLs in system search directories.
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading**: Sideloading malicious dynamic libraries into trusted application paths.
* **T1068 - Exploitation for Privilege Escalation**: Leveraging filesystem and object manager permission flaws to elevate privileges from standard user to SYSTEM.

---

## Legacy Impact & Compatibility
* **Standard Win32 Applications**: Commercial software compliant with Windows Vista/7/10/11 certification requirements writes user configuration data to `%AppData%` and `%LocalAppData%` rather than `%SystemRoot%`. Such software is completely unaffected.
* **Legacy 16-Bit / Early Windows XP Applications**: Obsolete applications designed to write configuration `.ini` files or data directly to `C:\Windows` will fail unless updated or relocated to user-writable directories.
* **Deployment Testing**: Validate custom internal corporate software in staging environments before enterprise-wide enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
4. Right-click **Registry** -> **New** -> **Registry Item** and configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Control\Session Manager`
   * **Value Name**: `ProtectionMode`
   * **Value Type**: `REG_DWORD`
   * **Value Data**: `1`
5. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.
6. Note: Enforcing `ProtectionMode` requires a computer restart to apply to the Session Manager during initial boot.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Directory Protection Mode:

[Download Script: Configure-EndAuditProtectionmode.ps1](../implementation_scripts/Configure-EndAuditProtectionmode.ps1)

```powershell
# Configure-EndAuditProtectionmode.ps1
Write-Host "Enforcing System Mitigation control: protection-mode..." -ForegroundColor Cyan

# Set Registry value: ProtectionMode
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord -Force
Write-Host "    Enforced ProtectionMode = 1" -ForegroundColor Green


```

*To audit the hardening status:*

[Download Script: Get-EndAuditProtectionmodeStatus.ps1](../audit_scripts/Get-EndAuditProtectionmodeStatus.ps1)

```powershell
# Get-EndAuditProtectionmodeStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: ProtectionMode
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.ProtectionMode -ne 1) {
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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000090, Windows 11 STIG Rule WN11-CC-000090
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and directory object permissions)
* **Microsoft Security Guidance**: Windows NT Session Manager Subsystem Architecture and Directory Protection
