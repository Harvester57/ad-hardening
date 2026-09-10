# [REQ-END-138] User Profile: Windows Installer Hardening

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-127](../../07-paws/user-profile/configure-up-installer-hardening.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
    * Value Data: `0` (Disabled / Prohibit unprivileged elevated installations)
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
Windows Installer (`msiexec.exe`) executes as a privileged Windows service (`NT AUTHORITY\SYSTEM`) to manage the installation, repair, and removal of software packages across the operating system. Misconfigurations in Windows Installer policies introduce some of the most critical, well-known Local Privilege Escalation (LPE) vulnerabilities in the Windows operating system.

### 1. Windows Installer Architecture & AlwaysInstallElevated Weaponization
The `AlwaysInstallElevated` policy instructs the Windows Installer service to execute all `.msi` packages with full administrative privileges (`NT AUTHORITY\SYSTEM`), even when invoked by an unprivileged standard user:
* If both machine and user policies are enabled (`AlwaysInstallElevated = 1`), an unprivileged standard user can craft or generate a custom MSI package containing an embedded executable or DLL (e.g., via tools like Metasploit, msfvenom, or WiX).
* When the user executes `msiexec /quiet /i malicious.msi`, the service executes the payload as `SYSTEM`, completely bypassing User Account Control (UAC) and local access controls.
* Ensuring `AlwaysInstallElevated = 0` at both the machine and user policy levels guarantees that Windows Installer strictly drops privileges or requires full administrative elevation via UAC credential validation.

### 2. User Control, SafeForScripting, and Device Co-Installer Hardening
* **EnableUserControl (`0`)**: Prevents standard users from overriding public installation properties (such as `TARGETDIR` or custom action parameters) from the command line, stopping directory traversal and arbitrary file write attacks during installations.
* **SafeForScripting (`0`)**: Blocks Web-based or unverified scripting engines from invoking Windows Installer actions marked as "safe for scripting," closing browser-based drive-by installer exploits.
* **DisableCoInstallers (`1`)**: Hardware device drivers often register "co-installers"—dynamic link libraries that execute during hardware detection. Threat actors can abuse plug-and-play events or virtual hardware attachments to trigger vulnerable or unquoted third-party co-installer DLLs that execute in `SYSTEM` context. Disabling co-installers eliminates this device installation attack surface.

### 3. MITRE ATT&CK Mapping
* **T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control**: Exploiting AlwaysInstallElevated to gain SYSTEM execution.
* **T1574.002 - Hijack Execution Flow: DLL Side-Loading**: Coercing Windows Installer or device co-installers into loading unauthorized dynamic modules.
* **T1068 - Exploitation for Privilege Escalation**: Escalating from standard user privileges to SYSTEM via misconfigured installer properties.

---

## Legacy Impact & Compatibility
* **Enterprise Software Distribution**: Centrally managed software deployment systems (Microsoft Intune, Microsoft Endpoint Configuration Manager / MECM, Group Policy Software Installation) operate via native administrative service accounts and are unaffected by these restrictions.
* **Standard User Self-Service**: Standard non-administrative users will not be able to execute MSI packages that require system-level changes without an administrative UAC prompt. This is the desired enterprise security posture.
* **Device Installations**: Approved WHQL-certified drivers that do not rely on legacy co-installer DLLs install normally.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Installer`
  * **Always install with elevated privileges**: Set to **Disabled**
  * **Allow user control over installs**: Set to **Disabled**
* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Installer`
  * **Always install with elevated privileges**: Set to **Disabled**
* Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
  * Add Registry Item: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\DisableCoInstallers` = `1` (DWord)

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the Windows Installer hardening settings:

[Download Script: Configure-Upinstallerhardening.ps1](../implementation_scripts/Configure-Upinstallerhardening.ps1)

```powershell
# Configure-Upinstallerhardening.ps1
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

[Download Script: Get-UpinstallerhardeningStatus.ps1](../audit_scripts/Get-UpinstallerhardeningStatus.ps1)

```powershell
# Get-UpinstallerhardeningStatus.ps1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x (Windows Installer); CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000120, Windows 11 STIG Rule WN11-CC-000120
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and preventing privilege elevation pathways)
* **Microsoft Security Guidance**: Windows Installer Best Practices: Preventing AlwaysInstallElevated Abuse
