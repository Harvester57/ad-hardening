# [REQ-END-127] User Profile: Spotlight and Consumer Features Restrictions

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-116](../../07-paws/user-profile/configure-up-spotlight-consumer.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **Turn Off Microsoft Consumer Experiences (Machine-Wide)**:
    * GPO Path: `Computer Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off Microsoft consumer experiences` -> **Enabled**
    * Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
    * Value Name: `DisableWindowsConsumerFeatures`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block automatic consumer app pre-installation)
  * **Disable Third-Party Suggestions in Windows Spotlight**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Cloud Content\Do not show third-party suggestions in Windows spotlight` -> **Enabled**
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\CloudContent`
    * Value Name: `DisableThirdPartySuggestions`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Suppress sponsored recommendations)
  * **Configure Windows Spotlight on Lock Screen**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Cloud Content\Configure Windows spotlight on lock screen` -> **Disabled**
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\CloudContent`
    * Value Name: `ConfigureWindowsSpotlight`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Disabled / Turn off dynamic lock screen cloud content)
  * **Turn Off Windows Spotlight on Desktop**:
    * GPO Path: `User Configuration\Administrative Templates\Windows Components\Cloud Content\Turn off Windows spotlight on desktop` -> **Enabled**
    * Registry Path: `HKCU\Software\Policies\Microsoft\Windows\CloudContent`
    * Value Name: `DisableSpotlightCollectionOnDesktop`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Block desktop background cloud rotation)

---

## Rationale
Windows consumer experiences and Windows Spotlight are cloud-integrated features designed to deliver targeted application suggestions, promotional tiles, interactive lock screen imagery, and tips to consumer endpoints. In an enterprise Active Directory domain, these features introduce significant threat surfaces, outbound network connections, and unapproved software provisioning.

### 1. Cloud Content Subsystem Architecture & Consumer Provisioning
The Windows Cloud Content subsystem (`ContentDeliveryManager`) connects to Microsoft cloud services to retrieve dynamic content:
* **Microsoft Consumer Experiences**: When a new user logs into a workstation, `ContentDeliveryManager` automatically schedules background downloads of third-party consumer applications, casual games, and promotional app packages directly into the user's `%LocalAppData%\Packages` directory.
* **Windows Spotlight**: Regularly connects to Microsoft Content Delivery Networks (CDNs) over HTTPS to download lock screen wallpapers, interactive overlays, and web-based tips.
* **Third-Party Suggestions**: Injects promoted software links and recommendations directly into the Windows Start Menu, Search pane, and Settings app.

### 2. Threat Vectors & Enterprise Exposure
* **Unvetted Software Provisioning**: Permitting consumer experiences allows unapproved third-party games and consumer utilities to be automatically installed on managed workstations, cluttering AppLocker/WDAC audit logs and potentially introducing vulnerabilities.
* **Data Leakage & Profiling**: Spotlight and consumer feature services transmit device metadata, hardware identifiers, and regional usage patterns to Microsoft cloud endpoints, conflicting with corporate data privacy and compliance mandates.
* **Bandwidth and Resource Waste**: Continuous background polling and downloading of high-resolution photographic collections and promotional packages consume network bandwidth and local storage cycles.
* Setting `DisableWindowsConsumerFeatures = 1` along with user-level Spotlight suppression locks down the desktop environment to sanctioned corporate applications only.

### 3. MITRE ATT&CK Mapping
* **T1497 - Virtualization/Sandbox Evasion / Environmental Discovery**: Cloud feature activity complicating forensic baselining and network traffic analysis.
* **T1059 - Command and Scripting Interpreter**: Background execution of provisioning scripts during consumer app installation.
* **T1082 - System Information Discovery**: Exfiltration of system telemetry and user profiling data through cloud content channels.

---

## Legacy Impact & Compatibility
* **Corporate Wallpaper and Branding**: Organizations deploying enterprise branding, corporate lock screen imagery, or custom wallpaper via Group Policy will benefit from predictable, static image displays without Spotlight overrides.
* **App Provisioning Integrity**: Users will experience a clean Start Menu free of third-party games or sponsored consumer links.
* **Operational Impact**: None. Core operating system functions, Windows Update, and Microsoft Store enterprise apps operate normally.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
  * **Turn off Microsoft consumer experiences**: Set to **Enabled**
* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
  * **Do not show third-party suggestions in Windows spotlight**: Set to **Enabled**
  * **Configure Windows spotlight on lock screen**: Set to **Disabled**
  * **Turn off Windows spotlight on desktop**: Set to **Enabled**

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Spotlight and Consumer Features restrictions:

[Download Script: Configure-Upspotlightconsumer.ps1](../implementation_scripts/Configure-Upspotlightconsumer.ps1)

```powershell
# Configure-Upspotlightconsumer.ps1
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
    Set-ItemProperty -Path $DefaultKey -Name "ConfigureWindowsSpotlight" -Value "2" -Type DWord -Force
    Set-ItemProperty -Path $DefaultKey -Name "DisableSpotlightCollectionOnDesktop" -Value "1" -Type DWord -Force
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
}

```

*To audit the hardening status:*

[Download Script: Get-UpspotlightconsumerStatus.ps1](../audit_scripts/Get-UpspotlightconsumerStatus.ps1)

```powershell
# Get-UpspotlightconsumerStatus.ps1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.9.x (Cloud Content); CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.9.x
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000140, Windows 11 STIG Rule WN11-CC-000140
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing user profiles and disabling unapproved cloud content)
* **Microsoft Security Guidance**: Managing Windows Cloud Content and Consumer Experiences in the Enterprise
