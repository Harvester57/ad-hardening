# [REQ-END-129] User Profile: In-Place Sharing Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInplaceSharing` = `1` (DWord)


---

## Rationale
Disables direct in-place shell context sharing actions to prevent rapid local file redistribution bypasses.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Network Sharing`
2. Configure the policy:
   * **Policy**: `Prevent users from sharing files within their profile.` -> Set to **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upinplacesharing.ps1](../implementation_scripts/Configure-Upinplacesharing.ps1)

```powershell
# Configure-Upinplacesharing.ps1
Write-Host "Applying User Profile restriction: inplace-sharing..." -ForegroundColor Cyan

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
Set-RegValue "HKCU:" "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "NoInplaceSharing" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*
[Download Script: Get-UpinplacesharingStatus.ps1](../audit_scripts/Get-UpinplacesharingStatus.ps1)

```powershell
# Get-UpinplacesharingStatus.ps1
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
Test-RegValue "HKCU:" "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoInplaceSharing" "1"

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
