# [REQ-PAW-127] User Profile: Windows Installer Hardening for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-138](../../08-endpoints/user-profile/configure-up-installer-hardening.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Always Install Elevated Lockdown (Machine & User)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges` -> **Disabled**
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Windows Installer\Always install with elevated privileges` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
    * Value Name: `AlwaysInstallElevated`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Strictly prohibit unprivileged elevated installations)
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\Installer`
    * Value Name: `AlwaysInstallElevated`
    * Value Type: `REG_DWORD`
    * Value Data: `0`
  * **Prevent User Control Over Installation Properties**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Installer\Prevent users from using command line options to install other programs` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
    * Value Name: `EnableUserControl`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Restrict user override of installation properties)
  * **Safe for Scripting Lockdown**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Windows Installer\Allow user control over installs` -> **Disabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`
    * Value Name: `SafeForScripting`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)
  * **Disable Device Co-Installers**:
    * Registry Path: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer`
    * Value Name: `DisableCoInstallers`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block third-party device co-installer DLL execution)

---

## Rationale
Privileged Access Workstations (PAWs) serve as the dedicated management boundary for Tier 0 Active Directory assets. In a hardened PAW environment, local software installations are strictly restricted to enterprise-vetted administrative tooling deployed via central configuration management. Permitting any permissive Windows Installer settings—especially `AlwaysInstallElevated`—presents an immediate local privilege escalation hazard that could allow a non-administrative account or background worker to seize full `NT AUTHORITY\SYSTEM` control of the PAW.

### 1. Windows Installer Architecture & AlwaysInstallElevated Weaponization
Windows Installer (`msiexec.exe`) executes as a privileged Windows service operating under the `NT AUTHORITY\SYSTEM` account:
* When `AlwaysInstallElevated` is configured to `1` in both machine and user hives, the operating system bypasses all security checks and runs all `.msi` packages with full system privileges, regardless of the calling user's integrity level.
* An attacker with standard or restricted access to a workstation can create a weaponized MSI package containing malicious scripts, registry overrides, or executable implants.
* Executing `msiexec /quiet /i exploit.msi` invokes the Windows Installer service to execute the embedded payload as `SYSTEM`.
* On a PAW console, an attacker who obtains `SYSTEM` privileges can bypass local security tools, compromise the LSA subsystem, inject into RSAT processes, and siphon Domain Admin Kerberos credentials.

### 2. Tier 0 Hardening & Device Co-Installer Suppression
* **EnableUserControl (`0`)**: Restricts non-administrative users from modifying installer runtime parameters, preventing attacks that redirect installation binaries to arbitrary system directories.
* **SafeForScripting (`0`)**: Blocks Web-based or script-driven actions from launching Windows Installer routines without full administrative verification.
* **DisableCoInstallers (`1`)**: Device co-installers are dynamic libraries invoked during hardware detection that run under the `SYSTEM` security context. On a PAW, physical peripheral attachments are restricted to approved keyboards and mice; disabling co-installers ensures that malicious USB or Thunderbolt devices cannot trigger vulnerable third-party driver setup DLLs.

### 3. MITRE ATT&CK Mapping
* **T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control**: Exploiting AlwaysInstallElevated to gain SYSTEM execution.
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading**: Coercing Windows Installer or device co-installers into loading unauthorized dynamic modules.
* **T1068 - Exploitation for Privilege Escalation**: Escalating from standard user privileges to SYSTEM via misconfigured installer properties.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: Interactive software installations on PAWs are strictly barred. All management utilities (RSAT, administrative modules) are pre-installed during image deployment or distributed via enterprise management channels.
* **Zero Disruption**: Daily administrative operations, directory querying, and PowerShell management scripts are completely unaffected by these policies.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Installer`
  * **Always install with elevated privileges**: Set to **Disabled**
  * **Allow user control over installs**: Set to **Disabled**
* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Installer`
  * **Always install with elevated privileges**: Set to **Disabled**
* Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
  * Add Registry Item: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\DisableCoInstallers` = `1` (DWord)

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to enforce Windows Installer hardening on the PAW console:

[Download Script: Configure-PawUpinstallerhardening.ps1](../implementation_scripts/Configure-PawUpinstallerhardening.ps1)

```powershell
# Configure-PawUpinstallerhardening.ps1
Write-Host "Applying User Profile restriction: installer-hardening..." -ForegroundColor Cyan

function Set-RegValue {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$value,
        [string]$type
    )
    if ($PSCmdlet.ShouldProcess("$hive\$keyPath", "Set registry value $name to $value")) {
        $fullPath = "$hive\$keyPath"
        $parent = Split-Path -Path $fullPath
        if (-not (Test-Path $parent)) { New-Item -Path $parent -Force | Out-Null }
        if (-not (Test-Path $fullPath)) { New-Item -Path $fullPath -Force | Out-Null }
        Set-ItemProperty -Path $fullPath -Name $name -Value $value -Type $type -Force
    }
}
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" "DisableCoInstallers" "1" "DWord"

```

*To audit the hardening status:*

[Download Script: Get-PawUpinstallerhardeningStatus.ps1](../audit_scripts/Get-PawUpinstallerhardeningStatus.ps1)

```powershell
# Get-PawUpinstallerhardeningStatus.ps1
$script:Vulnerable = $false

function Test-RegValue {
    param (
        [string]$hive,
        [string]$keyPath,
        [string]$name,
        [string]$expected
    )
    $fullPath = "$hive\$keyPath"
    $val = Get-ItemProperty -Path $fullPath -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    if ($actual -ne $expected) {
        $script:Vulnerable = $true
    }
}
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Installer" "SafeForScripting" "0"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" "DisableCoInstallers" "1"

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
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000120, Windows 11 STIG Rule WN11-CC-000120
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing privilege elevation pathways)
* **Microsoft Privileged Access Guidance**: Securing Privileged Access: System-Level Hardening and Memory Protections
