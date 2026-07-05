# [REQ-END-134] User Profile: Explorer Security and Memory Protections

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention` = `0` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption` = `0` (DWord)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior` = `0` (DWord)


---

## Rationale
Enforces Data Execution Prevention (DEP) and Heap Termination on Corruption inside Windows Explorer and disables pre-XP SP2 shell protocol behaviors.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer`
2. Configure the policies:
   * **Policy**: `Turn off Data Execution Prevention for Explorer` -> Set to **Disabled** (keeps DEP active)
   * **Policy**: `Turn off heap termination on corruption` -> Set to **Disabled** (keeps Heap Termination active)
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ File Explorer` (or User configuration equivalent)
4. Configure the policy:
   * **Policy**: `Shell Protocol Protected Mode` -> Set to **Enabled** (enforces PreXPSP2ShellProtocolBehavior = 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upexplorersecurity.ps1](../implementation_scripts/Configure-Upexplorersecurity.ps1)

```powershell
# Configure-Upexplorersecurity.ps1
Write-Host "Applying User Profile restriction: explorer-security..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-UpexplorersecurityStatus.ps1](../audit_scripts/Get-UpexplorersecurityStatus.ps1)

```powershell
# Get-UpexplorersecurityStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption" "0"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior" "0"

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
