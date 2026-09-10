# [REQ-PAW-116] User Profile: Spotlight and Consumer Features Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 Active Directory and identity infrastructure administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-127](../../08-endpoints/user-profile/configure-up-spotlight-consumer.md)).*
* **Operating Systems**: Windows 10 Enterprise (version 1809 and above), Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) operate in dedicated management enclaves with restricted internet egress. Connecting to public consumer clouds to download wallpapers, marketing suggestions, or consumer games introduces unvetted network connections, violates administrative isolation, and increases attack surface on Tier 0 assets.

### 1. Cloud Content Subsystem & PAW Threat Boundary
The Windows Cloud Content delivery pipeline connects to public Microsoft CDNs:
* In standard Windows desktop installations, `ContentDeliveryManager` initiates unauthenticated HTTPS connections to fetch lock screen images, tips, and third-party consumer packages.
* On a PAW console, outbound internet access must be strictly restricted or completely blocked by perimeter firewalls. Unconstrained cloud feature polling generates extraneous network traffic, alerts in firewall/proxy logs, and potential outbound information leakage (system telemetry and hardware GUIDs).
* Furthermore, consumer app provisioning could dynamically install non-enterprise AppX packages that expand the local software footprint, bypassing intended baseline minimalism.

### 2. Tier 0 Architectural Isolation & Hygiene
* **Minimalist Host Architecture**: Dedicated PAW consoles must maintain the absolute minimum footprint of installed software, services, and background tasks. Suppressing consumer experiences prevents the operating system from staging casual games, consumer shortcuts, or unapproved store applications.
* **Lock Screen and Desktop Predictability**: Disabling Spotlight locks the desktop and lock screen backgrounds to approved, static corporate images, eliminating background network queries to public CDNs.
* **Surface Reduction**: Terminating third-party suggestions ensures that administrative consoles remain clean, professional, and free from external web-driven content feeds.

### 3. MITRE ATT&CK Mapping
* **T1497 - Virtualization/Sandbox Evasion / Environmental Discovery**: Background consumer traffic introducing noise into network monitoring.
* **T1059 - Command and Scripting Interpreter**: Automated installation routines triggered by consumer package managers.
* **T1082 - System Information Discovery**: Background telemetry and machine profiling data sent to external cloud services.

---

## Legacy Impact & Compatibility
* **PAW Dedicated Role**: PAWs are dedicated exclusively to domain administration. Consumer applications, casual games, and dynamic desktop tips have no place on Tier 0 infrastructure.
* **Zero Operational Disruption**: Core administrative tools, RSAT, and Active Directory administrative workflows operate without disruption.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to Tier 0 Privileged Access Workstations (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
  * **Turn off Microsoft consumer experiences**: Set to **Enabled**
* Navigate to: `User Configuration \ Administrative Templates \ Windows Components \ Cloud Content`
  * **Do not show third-party suggestions in Windows spotlight**: Set to **Enabled**
  * **Configure Windows spotlight on lock screen**: Set to **Disabled**
  * **Turn off Windows spotlight on desktop**: Set to **Enabled**

4. Link the GPO to the dedicated PAW Organizational Unit and enforce replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure Spotlight and Consumer Features restrictions on the PAW console:

[Download Script: Configure-PawUpspotlightconsumer.ps1](../implementation_scripts/Configure-PawUpspotlightconsumer.ps1)

```powershell
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R37 (Securing administrative workstations and disabling cloud services)
* **Microsoft Privileged Access Guidance**: Clean Source Principle: PAW Software Footprint and Telemetry Lockdown
