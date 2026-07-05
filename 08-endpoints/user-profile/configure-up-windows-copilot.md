# [REQ-END-128] User Profile: Windows Copilot Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

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
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Windows Copilot`
2. Configure the policy:
   * **Policy**: `Turn off Windows Copilot` -> Set to **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upwindowscopilot.ps1](../implementation_scripts/Configure-Upwindowscopilot.ps1)

```powershell
# Configure-Upwindowscopilot.ps1
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
[Download Script: Get-UpwindowscopilotStatus.ps1](../audit_scripts/Get-UpwindowscopilotStatus.ps1)

```powershell
# Get-UpwindowscopilotStatus.ps1
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
* **CIS Microsoft Windows Benchmark**: User profile privacy and shell lockdown controls
* **ANSSI Active Directory Hardening Guide**: Client security baselines
