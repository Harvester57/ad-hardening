# [REQ-END-139] User Profile: Secondary Logon Service Lockdown

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SYSTEM\CurrentControlSet\Services\seclogon\Start` = `4` (DWord)


---

## Rationale
Disables the Secondary Logon service (seclogon) to prevent users from executing processes under alternate credentials via runas without proper validation.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure the registry values directly using Group Policy Preferences (Registry Items).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upseclogonservice.ps1](../implementation_scripts/Configure-Upseclogonservice.ps1)

```powershell
# Configure-Upseclogonservice.ps1
Write-Host "Applying User Profile restriction: seclogon-service..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Services\seclogon" "Start" "4" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-UpseclogonserviceStatus.ps1](../audit_scripts/Get-UpseclogonserviceStatus.ps1)

```powershell
# Get-UpseclogonserviceStatus.ps1
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
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Services\seclogon" "Start" "4"

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
