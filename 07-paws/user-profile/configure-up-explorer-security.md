# [REQ-PAW-123] User Profile: Explorer Security and Memory Protections for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
* **Operational Impact**: Restricts user customizations on administrative consoles. No operational impact is expected on dedicated PAW consoles.

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
[Download Script: Configure-PawUpexplorersecurity.ps1](../implementation_scripts/Configure-PawUpexplorersecurity.ps1)

```powershell
# Configure-PawUpexplorersecurity.ps1
# Configure-PawUpexplorersecurity.ps1
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
[Download Script: Get-PawUpexplorersecurityStatus.ps1](../audit_scripts/Get-PawUpexplorersecurityStatus.ps1)

```powershell
# Get-PawUpexplorersecurityStatus.ps1
# Get-PawUpexplorersecurityStatus.ps1
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
* **CIS Microsoft Windows Benchmark**: PAW workstation restrictions
* **ANSSI Active Directory Hardening Guide**: Workstation baseline guide
