# [REQ-END-140] User Profile: Exploit Guard and Speculative Mitigations

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Locations**:
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` = `0` (DWord)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode` = `1` (DWord)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImages` = `4294967295` (DWord)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride` = `72` (DWord)
  * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask` = `3` (DWord)
  * `HKLM\Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)
  * `HKLM\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck` = `1` (DWord)
  * `HKLM\SOFTWARE\Microsoft\Command Processor\LockBatchFilesWhenInUse` = `1` (DWord)
  * `HKLM\SOFTWARE\Microsoft\TTD\RecordingPolicy` = `2` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags` = `1` (DWord)
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs` = `0` (DWord)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation` = `2` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR` = `0` (DWord)
  * `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace` = `1` (DWord)


---

## Rationale
Enforces Address Space Layout Randomization (ASLR) force relocation, Spectre/Meltdown speculative execution overrides, SEHOP, time-travel debugging recording locks, Authenticode padding validation, and AppInit DLL bans.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts client customization features. Verify compatibility in staging environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Define secondary logon service startup type:
   * Navigate to: `Computer Configuration \ Policies \ Windows Settings \ Security Settings \ System Services`
   * Double-click `Secondary Logon`, check **Define this policy setting**, and set startup mode to **Disabled**
2. Configure Attachment Zone retention:
   * Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Attachment Manager`
   * Configure the policy:
     * **Policy**: `Do not preserve zone information in file attachments` -> Set to **Disabled** (forces SaveZoneInformation = 2)
3. Configure Windows Ink Workspace above lock restrictions:
   * Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Windows Ink Workspace`
   * Configure the policy:
     * **Policy**: `Allow Windows Ink Workspace` -> Set to **Enabled** and select **On, but disallow clicks above lock** (value 1)
4. Deploy the remaining custom system mitigation registry preferences:
   * Navigate to: `Computer Configuration \ Preferences \ Windows Settings \ Registry`
   * Create new **Registry Items** for:
     * **ASLR Force Randomization**: Key `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Value `MoveImages` = `0xFFFFFFFF` (DWord)
     * **CPU Spectre Overrides**: Key `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management` | Value `FeatureSettingsOverride` = `72` (DWord), `FeatureSettingsOverrideMask` = `3` (DWord)
     * **System Objects Protection**: Key `SYSTEM\CurrentControlSet\Control\Session Manager` | Value `ProtectionMode` = `1` (DWord)
     * **Strict Authenticode cert padding check**: Key `Software\Microsoft\Cryptography\Wintrust\Config` | Value `EnableCertPaddingCheck` = `1` (DWord) and Wow6432Node equivalent.
     * **Secure Batch Processing**: Key `SOFTWARE\Microsoft\Command Processor` | Value `LockBatchFilesWhenInUse` = `1` (DWord)
     * **Disable Time-Travel Debugging**: Key `SOFTWARE\Microsoft\TTD` | Value `RecordingPolicy` = `2` (DWord)
     * **Protected Roots Flags**: Key `SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots` | Value `Flags` = `1` (DWord)
     * **Disable AppInit DLLs**: Key `Software\Microsoft\Windows NT\CurrentVersion\Windows` | Value `LoadAppInit_DLLs` = `0` (DWord)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-Upsystemmitigations.ps1](../implementation_scripts/Configure-Upsystemmitigations.ps1)

```powershell
# Configure-Upsystemmitigations.ps1
Write-Host "Applying User Profile restriction: system-mitigations..." -ForegroundColor Cyan

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
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" "4294967295" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" "72" "DWord"
Set-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3" "DWord"
Set-RegValue "HKLM:" "Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1" "DWord"
Set-RegValue "HKLM:" "Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" "1" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\TTD" "RecordingPolicy" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" "1" "DWord"
Set-RegValue "HKLM:" "Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "2" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0" "DWord"
Set-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1" "DWord"

```

*To audit the hardening status:*
[Download Script: Get-UpsystemmitigationsStatus.ps1](../audit_scripts/Get-UpsystemmitigationsStatus.ps1)

```powershell
# Get-UpsystemmitigationsStatus.ps1
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
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation" "0"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "MoveImages" "4294967295"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride" "72"
Test-RegValue "HKLM:" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask" "3"
Test-RegValue "HKLM:" "Software\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1"
Test-RegValue "HKLM:" "Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" "1"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Command Processor" "LockBatchFilesWhenInUse" "1"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\TTD" "RecordingPolicy" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" "Flags" "1"
Test-RegValue "HKLM:" "Software\Microsoft\Windows NT\CurrentVersion\Windows" "LoadAppInit_DLLs" "0"
Test-RegValue "HKLM:" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" "SaveZoneInformation" "2"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0"
Test-RegValue "HKLM:" "SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace" "1"

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
