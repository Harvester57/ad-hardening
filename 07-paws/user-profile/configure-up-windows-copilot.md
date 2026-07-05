# [REQ-PAW-117] User Profile: Windows Copilot Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot` = `1` (DWord)


---

## Rationale
Disables the Windows Copilot assistant to prevent unauthorized data exfiltration or automated context parsing of local user activity.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts user customizations on administrative consoles. No operational impact is expected on dedicated PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
2. Configure the policy:
   * **Policy**: `Turn off Windows Copilot` -> Set to **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUpwindowscopilot.ps1](../implementation_scripts/Configure-PawUpwindowscopilot.ps1)

```powershell
# Configure-PawUpwindowscopilot.ps1
# Configure-PawUpwindowscopilot.ps1
Write-Host "Applying User Profile restriction: windows-copilot..." -ForegroundColor Cyan

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
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "TurnOffWindowsCopilot" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*
[Download Script: Get-PawUpwindowscopilotStatus.ps1](../audit_scripts/Get-PawUpwindowscopilotStatus.ps1)

```powershell
# Get-PawUpwindowscopilotStatus.ps1
# Get-PawUpwindowscopilotStatus.ps1
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
Test-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\WindowsCopilot" "TurnOffWindowsCopilot" "1"

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
