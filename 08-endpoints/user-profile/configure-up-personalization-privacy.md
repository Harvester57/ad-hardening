# [REQ-END-131] User Profile: Personalization and Privacy Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock` = `2` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization\AllowInputPersonalization` = `0` (DWord)


---

## Rationale
Disables lock screen cameras, lock screen slideshows, voice activation above lock, and input personalization (speech/typing logs) to preserve local workstation privacy.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Personalization`
2. Configure the policies:
   * **Policy**: `Prevent enabling lock screen camera` -> Set to **Enabled**
   * **Policy**: `Prevent enabling lock screen slide show` -> Set to **Enabled**
3. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ App Privacy`
4. Configure the policy:
   * **Policy**: `Let Windows apps activate with voice while the system is locked` -> Set to **Enabled** and select **Force Deny** (value 2)
5. Navigate to: `Computer Configuration \ Administrative Templates \ Control Panel \ Regional and Language Options`
6. Configure the policy:
   * **Policy**: `Allow users to enable online speech recognition services` -> Set to **Disabled** (value 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Uppersonalizationprivacy.ps1](../implementation_scripts/Configure-Uppersonalizationprivacy.ps1)

```powershell
# Configure-Uppersonalizationprivacy.ps1
Write-Host "Applying User Profile restriction: personalization-privacy..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-UppersonalizationprivacyStatus.ps1](../audit_scripts/Get-UppersonalizationprivacyStatus.ps1)

```powershell
# Get-UppersonalizationprivacyStatus.ps1
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
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenSlideshow" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0"

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
