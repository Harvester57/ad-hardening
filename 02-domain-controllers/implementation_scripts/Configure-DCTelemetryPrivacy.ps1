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
