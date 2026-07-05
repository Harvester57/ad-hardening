# [REQ-PAW-119] User Profile: Shell RunAs User Suppression for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Classes\batfile\shell\runasuser\SuppressionPolicy` = `4096` (DWord)
  * `HKLM\SOFTWARE\Classes\cmdfile\shell\runasuser\SuppressionPolicy` = `4096` (DWord)
  * `HKLM\SOFTWARE\Classes\exefile\shell\runasuser\SuppressionPolicy` = `4096` (DWord)
  * `HKLM\SOFTWARE\Classes\mscfile\shell\runasuser\SuppressionPolicy` = `4096` (DWord)


---

## Rationale
Suppresses the 'Run as different user' shell context menu for scripts and executables to prevent users from bypassing local validation structures.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts user customizations on administrative consoles. No operational impact is expected on dedicated PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy custom registry preferences under: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
2. Create four new **Registry Items** for bat, cmd, exe, and msc file RunAs suppression:
   * **Registry Item 1**:
     * **Key Path**: `SOFTWARE\Classes\batfile\shell\runasuser`
     * **Value name**: `SuppressionPolicy`
     * **Value type**: REG_DWORD
     * **Value data**: `4096`
   * **Registry Item 2**:
     * **Key Path**: `SOFTWARE\Classes\cmdfile\shell\runasuser`
     * **Value name**: `SuppressionPolicy`
     * **Value type**: REG_DWORD
     * **Value data**: `4096`
   * **Registry Item 3**:
     * **Key Path**: `SOFTWARE\Classes\exefile\shell\runasuser`
     * **Value name**: `SuppressionPolicy`
     * **Value type**: REG_DWORD
     * **Value data**: `4096`
   * **Registry Item 4**:
     * **Key Path**: `SOFTWARE\Classes\mscfile\shell\runasuser`
     * **Value name**: `SuppressionPolicy`
     * **Value type**: REG_DWORD
     * **Value data**: `4096`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUprunassuppression.ps1](../implementation_scripts/Configure-PawUprunassuppression.ps1)

```powershell
# Configure-PawUprunassuppression.ps1
# Configure-PawUprunassuppression.ps1
Write-Host "Applying User Profile restriction: runas-suppression..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "4096" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-PawUprunassuppressionStatus.ps1](../audit_scripts/Get-PawUprunassuppressionStatus.ps1)

```powershell
# Get-PawUprunassuppressionStatus.ps1
# Get-PawUprunassuppressionStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Classes\batfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\cmdfile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\exefile\shell\runasuser" "SuppressionPolicy" "4096"
Test-RegValue "HKLM:" "SOFTWARE\Classes\mscfile\shell\runasuser" "SuppressionPolicy" "4096"

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
* **CIS Microsoft Windows Benchmark**: PAW workstation restrictions
* **ANSSI Active Directory Hardening Guide**: Workstation baseline guide
