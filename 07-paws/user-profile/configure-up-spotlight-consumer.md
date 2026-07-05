# [REQ-PAW-116] User Profile: Spotlight and Consumer Features Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKCU\Software\Policies\Microsoft\Windows\CloudContent\DisableThirdPartySuggestions` = `1` (DWord)
  * `HKCU\Software\Policies\Microsoft\Windows\CloudContent\ConfigureWindowsSpotlight` = `2` (DWord)
  * `HKCU\Software\Policies\Microsoft\Windows\CloudContent\DisableSpotlightCollectionOnDesktop` = `1` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures` = `1` (DWord)


---

## Rationale
Disables Windows consumer features, Spotlight wallpaper suggestions, and third-party advertising in the shell to limit telemetry and prevent social-engineering application suggestions.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts user customizations on administrative consoles. No operational impact is expected on dedicated PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
2. Configure the policy:
   * **Policy**: `Turn off Microsoft consumer experiences` -> Set to **Enabled**
3. Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
4. Configure the policies:
   * **Policy**: `Do not suggest third-party content in Windows spotlight` -> Set to **Enabled**
   * **Policy**: `Configure Windows spotlight on lock screen` -> Set to **Enabled** (and select **Disabled** to turn off recommendations)
5. Deploy custom registry preference for desktop spotlight (HKCU):
   * Navigate to: `User Configuration \ Preferences \ Windows Settings \ Registry`
   * Create a new **Registry Item**:
     * **Action**: Update
     * **Hive**: HKEY_CURRENT_USER
     * **Key Path**: `Software\Policies\Microsoft\Windows\CloudContent`
     * **Value name**: `DisableSpotlightCollectionOnDesktop`
     * **Value type**: REG_DWORD
     * **Value data**: `1`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUpspotlightconsumer.ps1](../implementation_scripts/Configure-PawUpspotlightconsumer.ps1)

```powershell
# Configure-PawUpspotlightconsumer.ps1
# Configure-PawUpspotlightconsumer.ps1
Write-Host "Applying User Profile restriction: spotlight-consumer..." -ForegroundColor Cyan

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
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "1" "DWord"
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" "2" "DWord"
Set-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1" "DWord"

# Apply to Default User profile for new sessions
$DefaultHivePath = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultHivePath) {
    reg load HKU\DefaultUser $DefaultHivePath | Out-Null
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "DisableThirdPartySuggestions" -Value "1" -Type DWord -Force
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "ConfigureWindowsSpotlight" -Value "2" -Type DWord -Force
    $DefaultKey = "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $DefaultKey)) { New-Item -Path $DefaultKey -Force | Out-Null }
    Set-ItemProperty -Path $DefaultKey -Name "DisableSpotlightCollectionOnDesktop" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*
[Download Script: Get-PawUpspotlightconsumerStatus.ps1](../audit_scripts/Get-PawUpspotlightconsumerStatus.ps1)

```powershell
# Get-PawUpspotlightconsumerStatus.ps1
# Get-PawUpspotlightconsumerStatus.ps1
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
Test-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" "1"
Test-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "ConfigureWindowsSpotlight" "2"
Test-RegValue "HKCU:" "Software\Policies\Microsoft\Windows\CloudContent" "DisableSpotlightCollectionOnDesktop" "1"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" "1"

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
