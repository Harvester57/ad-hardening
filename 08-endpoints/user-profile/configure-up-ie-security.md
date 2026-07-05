# [REQ-END-135] User Profile: Internet Explorer Options and Feeds Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions` = `0` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear` = `0` (DWord)


---

## Rationale
Blocks basic cleartext authentication, disables feed enclosure downloads, and disables override options inside standard Internet Options panels.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Internet Explorer`
2. Configure the policy:
   * **Policy**: `Disable Internet Explorer 11 as a standalone browser` -> Set to **Enabled** and select **Always**
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ RSS Feeds`
4. Configure the policies:
   * **Policy**: `Prevent downloading of enclosures` -> Set to **Enabled**
   * **Policy**: `Turn on Basic feed authentication over HTTP` -> Set to **Disabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upiesecurity.ps1](../implementation_scripts/Configure-Upiesecurity.ps1)

```powershell
# Configure-Upiesecurity.ps1
Write-Host "Applying User Profile restriction: ie-security..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" "NotifyDisableIEOptions" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" "0" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-UpiesecurityStatus.ps1](../audit_scripts/Get-UpiesecurityStatus.ps1)

```powershell
# Get-UpiesecurityStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" "NotifyDisableIEOptions" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "AllowBasicAuthInClear" "0"

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
