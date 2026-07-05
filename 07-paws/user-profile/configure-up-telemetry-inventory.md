# [REQ-PAW-122] User Profile: Telemetry and Inventory Collection Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics` = `1` (DWord)


---

## Rationale
Disables application compatibility inventory scans and restricts telemetry uploads to the minimum baseline levels.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts user customizations on administrative consoles. No operational impact is expected on dedicated PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Application Compatibility`
2. Configure the policy:
   * **Policy**: `Turn off Inventory Collector` -> Set to **Enabled**
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Data Collection and Preview Builds`
4. Configure the policies:
   * **Policy**: `Allow Telemetry` -> Set to **Enabled** and select **1 - Basic** (or **1 - Required** depending on OS version)
   * **Policy**: `Limit Enhanced diagnostic data to the minimum required by Windows Analytics` -> Set to **Enabled** and select **1 - Enable Windows Analytics settings**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUptelemetryinventory.ps1](../implementation_scripts/Configure-PawUptelemetryinventory.ps1)

```powershell
# Configure-PawUptelemetryinventory.ps1
# Configure-PawUptelemetryinventory.ps1
Write-Host "Applying User Profile restriction: telemetry-inventory..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" "1" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-PawUptelemetryinventoryStatus.ps1](../audit_scripts/Get-PawUptelemetryinventoryStatus.ps1)

```powershell
# Get-PawUptelemetryinventoryStatus.ps1
# Get-PawUptelemetryinventoryStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitEnhancedDiagnosticDataWindowsAnalytics" "1"

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
