# [REQ-DC-027] Configure Telemetry, Diagnostics and Privacy Options for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Allow Online Tips**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\Control Panel\Allow Online Tips` -> Disabled
    * Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` -> `AllowOnlineTips` = `0` (REG_DWORD)
  * **Enable Font Providers**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\Network\Fonts\Enable Font Providers` -> Disabled
    * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` -> `EnableFontProviders` = `0` (REG_DWORD)
  * **Turn off notifications network usage**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\Start Menu and Taskbar\Turn off notifications network usage` -> Enabled
    * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications` -> `NoCloudApplicationNotification` = `1` (REG_DWORD)
  * **Handwriting Personalization & Error Reporting**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
      * `Turn off handwriting personalization data sharing` -> Enabled
      * `Turn off handwriting recognition error reporting` -> Enabled
    * Registry:
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC` -> `PreventHandwritingDataSharing` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports` -> `PreventHandwritingErrorReports` = `1` (REG_DWORD)
  * **Internet Communication Settings**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
      * `Turn off printing over HTTP` -> Enabled
      * `Turn off Search Companion content file updates` -> Enabled
      * `Turn off the "Order Prints" picture task` -> Enabled
      * `Turn off the "Publish to Web" task for files and folders` -> Enabled
      * `Turn off the Windows Messenger Customer Experience Improvement Program` -> Enabled
      * `Turn off Windows Customer Experience Improvement Program` -> Enabled
      * `Turn off Windows Error Reporting` -> Enabled
    * Registry:
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers` -> `DisableHTTPPrinting` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion` -> `DisableContentFileUpdates` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` -> `NoOnlinePrintsWizard` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` -> `NoPublishingWizard` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client` -> `CEIP` = `2` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows` -> `CEIPEnable` = `0` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting` -> `Disabled` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting` -> `DoReport` = `0` (REG_DWORD)
  * **Microsoft Support Diagnostic Tool (MSDT)**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider` -> Disabled
    * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy` -> `DisableQueryRemoteServer` = `0` (REG_DWORD)
  * **Turn off the advertising ID**:
    * GPO: `Computer Configuration\Policies\Administrative Templates\System\User Profiles\Turn off the advertising ID` -> Enabled
    * Registry: `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo` -> `DisabledByGroupPolicy` = `1` (REG_DWORD)
  * **Allow app data sharing / Camera**:
    * GPO:
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\App Package Deployment\Allow a Windows app to share application data between users` -> Disabled
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Camera\Allow Use of Camera` -> Disabled
    * Registry:
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager` -> `AllowSharedLocalAppData` = `0` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Camera` -> `AllowCamera` = `0` (REG_DWORD)
  * **Connected User Experience and Telemetry / Location / Messaging**:
    * GPO:
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Data Collection and Preview Builds\Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service` -> Enabled: Disable Authenticated Proxy usage
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Location and Sensors\Turn off location` -> Enabled
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Messaging\Allow Message Service Cloud Sync` -> Disabled
    * Registry:
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` -> `DisableEnterpriseAuthProxy` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors` -> `DisableLocation` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging` -> `AllowMessageSync` = `0` (REG_DWORD)
  * **Push to Install / Search Cloud / KMS Online / Ink Workspace**:
    * GPO:
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Push to Install\Turn off Push To Install service` -> Enabled
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow Cloud Search` -> Enabled: Disable Cloud Search
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Search\Allow search highlights` -> Disabled
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation` -> Enabled
      * `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Ink Workspace\Allow suggested apps in Windows Ink Workspace` -> Disabled
    * Registry:
      * `HKLM\SOFTWARE\Policies\Microsoft\PushToInstall` -> `DisablePushToInstall` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` -> `AllowCloudSearch` = `0` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search` -> `EnableDynamicContentInWSB` = `0` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform` -> `NoGenTicket` = `1` (REG_DWORD)
      * `HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace` -> `AllowSuggestedAppsInWindowsInkWorkspace` = `0` (REG_DWORD)
  * **User Configuration (Privacy & Feedback)**:
    * GPO (User Configuration):
      * `User Configuration\Policies\Administrative Templates\System\Internet Communication Management\Internet Communication Settings\Turn off Help Experience Improvement Program` -> Enabled
      * `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences` -> Enabled
      * `User Configuration\Policies\Administrative Templates\Windows Components\Cloud Content\Turn off all Windows spotlight features` -> Enabled
      * `User Configuration\Policies\Administrative Templates\Windows Components\Windows Media Player\Playback\Prevent Codec Download` -> Enabled
    * Registry:
      * `HKCU\Software\Policies\Microsoft\Assistance\Client\1.0` -> `NoImplicitFeedback` = `1` (REG_DWORD)
      * `HKCU\Software\Policies\Microsoft\Windows\CloudContent` -> `DisableTailoredExperiencesWithDiagnosticData` = `1` (REG_DWORD)
      * `HKCU\Software\Policies\Microsoft\Windows\CloudContent` -> `DisableWindowsSpotlightFeatures` = `1` (REG_DWORD)
      * `HKCU\Software\Policies\Microsoft\WindowsMediaPlayer` -> `PreventCodecDownload` = `1` (REG_DWORD)

---

## Rationale
Restricting telemetry, remote help channels, data sharing features, and diagnostic logs on Domain Controllers limits target exposure and data leakage:
1. **Minimize Telemetry and Personalization Leakage**: Domain Controllers process highly sensitive security directory events, administrative tasks, and structural secrets. Personalization telemetry (such as handwriting sharing, speech data, and Customer Experience Improvement Programs) sends host telemetry to external cloud endpoints.
2. **Disable Non-Essential Network Services**: Features like Online Help, printing over HTTP, and Windows Spotlight create unauthenticated outbound connections to cloud platforms.
3. **Restrict Diagnostic Tools**: Interactive diagnostic channels like the Microsoft Support Diagnostic Tool (MSDT) have been targeted in remote execution exploits (e.g., Follina). Restricting interactive troubleshooting tools prevents adversaries from utilizing diagnostic capabilities for code execution.
4. **Prevent Cloud Synchronization**: Message cloud synchronization, push-to-install services, and cloud-based search highlights run background processes that expose local queries and operations to external networks.

---

## Legacy Impact & Compatibility
* **Interactive Troubleshooting**: Automated help diagnostics or Microsoft Support online troubleshooting utilities will be blocked. Administrators must identify issues manually using local event viewer logs and offline diagnostics.
* **Search Highlights and Cloud Search**: Local Start menu searches will only index local server content and folders, ignoring web or cloud highlights, which is the preferred behavior for hardened server nodes.
* **KMS Online Validation**: The server will not attempt online KMS validation checks via Active Validation Service (AVS) client prompts. Activation should be managed using local Active Directory-Based Activation (ADBA) or KMS host infrastructure.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure Group Policy settings to disable telemetry and cloud services:

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the appropriate GPO targeting the Domain Controllers (e.g., `GPO_Hardening_DomainControllers`).
3. Configure the following settings under **Computer Configuration**:
   * `Control Panel\Allow Online Tips` -> **Disabled**
   * `Network\Fonts\Enable Font Providers` -> **Disabled**
   * `Start Menu and Taskbar\Turn off notifications network usage` -> **Enabled**
   * `System\Internet Communication Management\Internet Communication settings`:
     * `Turn off handwriting personalization data sharing` -> **Enabled**
     * `Turn off handwriting recognition error reporting` -> **Enabled**
     * `Turn off printing over HTTP` -> **Enabled**
     * `Turn off Search Companion content file updates` -> **Enabled**
     * `Turn off the "Order Prints" picture task` -> **Enabled**
     * `Turn off the "Publish to Web" task for files and folders` -> **Enabled**
     * `Turn off the Windows Messenger Customer Experience Improvement Program` -> **Enabled**
     * `Turn off Windows Customer Experience Improvement Program` -> **Enabled**
     * `Turn off Windows Error Reporting` -> **Enabled**
   * `System\Troubleshooting and Diagnostics\Microsoft Support Diagnostic Tool\Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider` -> **Disabled**
   * `System\User Profiles\Turn off the advertising ID` -> **Enabled**
   * `Windows Components\App Package Deployment\Allow a Windows app to share application data between users` -> **Disabled**
   * `Windows Components\Camera\Allow Use of Camera` -> **Disabled**
   * `Windows Components\Data Collection and Preview Builds\Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service` -> **Enabled: Disable Authenticated Proxy usage**
   * `Windows Components\Location and Sensors\Turn off location` -> **Enabled**
   * `Windows Components\Messaging\Allow Message Service Cloud Sync` -> **Disabled**
   * `Windows Components\Push to Install\Turn off Push To Install service` -> **Enabled**
   * `Windows Components\Search\Allow Cloud Search` -> **Enabled: Disable Cloud Search**
   * `Windows Components\Search\Allow search highlights` -> **Disabled**
   * `Windows Components\Software Protection Platform\Turn off KMS Client Online AVS Validation` -> **Enabled**
   * `Windows Components\Windows Ink Workspace\Allow suggested apps in Windows Ink Workspace` -> **Disabled**
4. Configure the following settings under **User Configuration** (or configure via GPO Preferences Registry if Loopback Processing is not active):
   * `System\Internet Communication Management\Internet Communication Settings\Turn off Help Experience Improvement Program` -> **Enabled**
   * `Windows Components\Cloud Content\Do not use diagnostic data for tailored experiences` -> **Enabled**
   * `Windows Components\Cloud Content\Turn off all Windows spotlight features` -> **Enabled**
   * `Windows Components\Windows Media Player\Playback\Prevent Codec Download` -> **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enforce telemetry and privacy registry hardening.

[Download Script: Configure-DCTelemetryPrivacy.ps1](implementation_scripts/Configure-DCTelemetryPrivacy.ps1)

```powershell
# Configure-DCTelemetryPrivacy.ps1
# Description: Configures telemetry, diagnostic, and privacy options for Domain Controllers.

Write-Host "Applying Telemetry and Privacy baseline settings..." -ForegroundColor Cyan

# Helper function to create keys and set values safely
function Set-RegDWord {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$path,
        [string]$name,
        [int]$value
    )
    if ($PSCmdlet.ShouldProcess($path, "Set registry DWORD value $name to $value")) {
        $parent = Split-Path -Path $path
        if (-not (Test-Path $parent)) {
            New-Item -Path $parent -Force | Out-Null
        }
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
    }
}

# 1. HKLM Policy Configurations
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates" 1
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard" 1
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP" 2
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace" 0

Write-Host "HKLM telemetry parameters configured." -ForegroundColor Green

# 2. Configure Current User Settings (HKCU)
$AssistancePath = "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0"
Set-RegDWord $AssistancePath "NoImplicitFeedback" 1

$CloudContentPath = "HKCU:\Software\Policies\Microsoft\Windows\CloudContent"
Set-RegDWord $CloudContentPath "DisableTailoredExperiencesWithDiagnosticData" 1
Set-RegDWord $CloudContentPath "DisableWindowsSpotlightFeatures" 1

$MediaPlayerPath = "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer"
Set-RegDWord $MediaPlayerPath "PreventCodecDownload" 1

Write-Host "HKCU telemetry parameters configured." -ForegroundColor Green

# 3. Configure Default User Hive Settings (HKU\DefaultUser)
$DefaultUserHive = "C:\Users\Default\NTUSER.DAT"
if (Test-Path $DefaultUserHive) {
    Write-Host "Loading Default User hive..." -ForegroundColor Gray
    reg load HKU\DefaultUser $DefaultUserHive | Out-Null
    
    Set-RegDWord "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" 1
    Set-RegDWord "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
    Set-RegDWord "Registry::HKU\DefaultUser\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1
    Set-RegDWord "Registry::HKU\DefaultUser\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" 1
    
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    reg unload HKU\DefaultUser | Out-Null
    Write-Host "Default User hive configurations applied." -ForegroundColor Green
} else {
    Write-Warning "Default User hive not found."
}

Write-Host "Telemetry and privacy settings applied successfully." -ForegroundColor Green
```

*To verify the settings have been applied:*

[Download Script: Get-DCTelemetryPrivacyStatus.ps1](audit_scripts/Get-DCTelemetryPrivacyStatus.ps1)

```powershell
# Get-DCTelemetryPrivacyStatus.ps1
# Description: Audits registry configuration of telemetry, diagnostic, and privacy settings on Domain Controllers.

Write-Host "--- Auditing Domain Controller Telemetry and Privacy Settings ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue ($path, $name, $expectedValue) {
    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    $color = "Red"
    if ($actual -eq $expectedValue) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $($name) | Actual: '$($actual)' (Expected: '$($expectedValue)')" -ForegroundColor $color
}

# 1. HKLM Audits
Write-Host "Auditing HKLM Settings..." -ForegroundColor Gray
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "AllowOnlineTips" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableFontProviders" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" "DisableContentFileUpdates" 1
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoOnlinePrintsWizard" 1
Test-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoPublishingWizard" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" "CEIP" 2
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" "DoReport" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" "DisableQueryRemoteServer" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Camera" "AllowCamera" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableEnterpriseAuthProxy" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall" "DisablePushToInstall" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "EnableDynamicContentInWSB" 0
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" "NoGenTicket" 1
Test-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowSuggestedAppsInWindowsInkWorkspace" 0

# 2. HKCU Audits
Write-Host "Auditing HKCU Settings..." -ForegroundColor Gray
Test-RegistryValue "HKCU:\Software\Policies\Microsoft\Assistance\Client\1.0" "NoImplicitFeedback" 1
Test-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
Test-RegistryValue "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1
Test-RegistryValue "HKCU:\Software\Policies\Microsoft\WindowsMediaPlayer" "PreventCodecDownload" 1

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.1.3 (Online Tips), Section 18.6.5 (Fonts), Section 18.8 (Push Notifications), Section 18.9.20 (Internet Communication Management), Section 18.9.47 (MSDT), Section 18.9.49 (Advertising ID), Section 18.10.4 (App Data Sharing), Section 18.10.11 (Camera), Section 18.10.16 (Telemetry Proxy), Section 18.10.37 (Location), Section 18.10.41 (Messaging Sync), Section 18.10.56 (Push to Install), Section 18.10.59 (Cloud Search), Section 18.10.63 (KMS Online AVS), Section 18.10.80 (Ink Workspace), Section 19.6.6 (Help Experience), Section 19.7.8 (Spotlight & Tailored Experiences), Section 19.7.46 (Codec Downloads)
* **ANSSI AD Hardening Guide**: Technical security baseline recommendations to restrict diagnostic tools, telemetry collection, and background service exposure.
