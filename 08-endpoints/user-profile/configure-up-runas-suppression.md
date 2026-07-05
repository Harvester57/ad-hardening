# [REQ-END-130] User Profile: Shell RunAs User Suppression

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

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
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

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
[Download Script: Configure-Uprunassuppression.ps1](../implementation_scripts/Configure-Uprunassuppression.ps1)

```powershell
# Configure-Uprunassuppression.ps1
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
[Download Script: Get-UprunassuppressionStatus.ps1](../audit_scripts/Get-UprunassuppressionStatus.ps1)

```powershell
# Get-UprunassuppressionStatus.ps1
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
* **CIS Microsoft Windows Benchmark**: User profile privacy and shell lockdown controls
* **ANSSI Active Directory Hardening Guide**: Client security baselines
