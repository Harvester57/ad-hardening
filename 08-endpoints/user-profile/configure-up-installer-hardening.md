# [REQ-END-138] User Profile: Windows Installer Hardening

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl` = `0` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` = `0` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting` = `0` (DWord)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\DisableCoInstallers` = `1` (DWord)


---

## Rationale
Enforces Windows Installer lockdowns by disabling AlwaysInstallElevated and blocking driver co-installer executions on endpoints.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Installer`
2. Configure the policies:
   * **Policy**: `Allow user control over installs` -> Set to **Disabled**
   * **Policy**: `Always install with elevated privileges` -> Set to **Disabled**
   * **Policy**: `Prevent Internet Explorer security prompt for Windows Installer scripts` -> Set to **Disabled**
3. Deploy custom registry preference for blocking driver co-installers:
   * Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
   * Create a new **Registry Item**:
     * **Action**: Update
     * **Hive**: HKEY_LOCAL_MACHINE
     * **Key Path**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer`
     * **Value name**: `DisableCoInstallers`
     * **Value type**: REG_DWORD
     * **Value data**: `1`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
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
* **CIS Microsoft Windows Benchmark**: User profile privacy and shell lockdown controls
* **ANSSI Active Directory Hardening Guide**: Client security baselines
