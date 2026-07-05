# Get-PawSystemAdministrativeTemplatesStatus.ps1
# Description: Audits 84 system and administrative template controls on the local PAW.

Write-Host "--- Auditing System Administrative Templates Hardening ---" -ForegroundColor Cyan
$script:Vulnerable = $false

function Test-RegValue {
    param(
        [string]$RecNum,
        [string]$Hive,
        [string]$KeyPath,
        [string]$ValueName,
        [object]$ExpectedValue
    )
    $FullPath = "$($Hive):\$($KeyPath)"
    if (Test-Path $FullPath) {
        $Prop = Get-ItemProperty -Path $FullPath -Name $ValueName -ErrorAction SilentlyContinue
        if ($null -ne $Prop) {
            $ActualValue = $Prop.$ValueName
            if ($ActualValue -eq $ExpectedValue) {
                Write-Host "  [+] $RecNum | $ValueName = $ActualValue (Secure)" -ForegroundColor Green
            } else {
                Write-Host "  [!] MISMATCH: $RecNum | Path: $Hive\$KeyPath | Value: $ValueName | Current: $ActualValue (Expected: $ExpectedValue)" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        } else {
            Write-Host "  [!] MISSING VALUE: $RecNum | Path: $Hive\$KeyPath | Value: $ValueName (Expected: $ExpectedValue)" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING KEY: $RecNum | Path: $Hive\$KeyPath (Expected: $ValueName = $ExpectedValue)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}

Test-RegValue -RecNum "18.4.2" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\mrxsmb10" -ValueName "Start" -ExpectedValue 4
Test-RegValue -RecNum "18.4.3" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -ExpectedValue 0
Test-RegValue -RecNum "18.4.7" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NodeType" -ExpectedValue 2
Test-RegValue -RecNum "18.5.1" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AutoAdminLogon" -ExpectedValue "0"
Test-RegValue -RecNum "18.5.2" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -ValueName "DisableIPSourceRouting" -ExpectedValue 2
Test-RegValue -RecNum "18.5.3" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "DisableIPSourceRouting" -ExpectedValue 2
Test-RegValue -RecNum "18.5.5" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "EnableICMPRedirect" -ExpectedValue 0
Test-RegValue -RecNum "18.5.7" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -ValueName "NoNameReleaseOnDemand" -ExpectedValue 1
Test-RegValue -RecNum "18.5.9" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Control\Session Manager" -ValueName "SafeDllSearchMode" -ExpectedValue 1
Test-RegValue -RecNum "18.5.10" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScreenSaverGracePeriod" -ExpectedValue 5
Test-RegValue -RecNum "18.5.13" -Hive "HKLM" -KeyPath "SYSTEM\CurrentControlSet\Services\Eventlog\Security" -ValueName "WarningLevel" -ExpectedValue 90
Test-RegValue -RecNum "18.9.7.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -ValueName "PreventDeviceMetadataFromNetwork" -ExpectedValue 1
Test-RegValue -RecNum "18.9.19.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoBackgroundPolicy" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoGPOListChanges" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoBackgroundPolicy" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}" -ValueName "NoGPOListChanges" -ExpectedValue 0
Test-RegValue -RecNum "18.9.19.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "EnableCdp" -ExpectedValue 0
Test-RegValue -RecNum "18.9.20.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Printers" -ValueName "DisableWebPnPDownload" -ExpectedValue 1
Test-RegValue -RecNum "18.9.20.1.6" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoWebServices" -ExpectedValue 1
Test-RegValue -RecNum "18.9.26.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowCustomSSPsAPs" -ExpectedValue 0
Test-RegValue -RecNum "18.9.28.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "BlockUserFromShowingAccountDetailsOnSignin" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontDisplayNetworkSelectionUI" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DontEnumerateConnectedUsers" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DisableLockScreenAppNotifications" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "BlockDomainPicturePassword" -ExpectedValue 1
Test-RegValue -RecNum "18.9.28.7" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "AllowDomainPINLogon" -ExpectedValue 0
Test-RegValue -RecNum "18.9.33.6.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -ValueName "DCSettingIndex" -ExpectedValue 0
Test-RegValue -RecNum "18.9.33.6.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -ValueName "ACSettingIndex" -ExpectedValue 0
Test-RegValue -RecNum "18.9.35.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "fAllowUnsolicited" -ExpectedValue 0
Test-RegValue -RecNum "18.9.36.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -ValueName "EnableAuthEpResolution" -ExpectedValue 1
Test-RegValue -RecNum "18.9.51.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" -ValueName "Enabled" -ExpectedValue 1
Test-RegValue -RecNum "18.9.51.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer" -ValueName "Enabled" -ExpectedValue 0
Test-RegValue -RecNum "18.10.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Appx" -ValueName "DisablePerUserUnsignedPackagesByDefault" -ExpectedValue 1
Test-RegValue -RecNum "18.10.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Appx" -ValueName "BlockNonAdminUserInstall" -ExpectedValue 1
Test-RegValue -RecNum "18.10.9.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" -ValueName "EnhancedAntiSpoofing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.13.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\CloudContent" -ValueName "DisableConsumerAccountStateContent" -ExpectedValue 1
Test-RegValue -RecNum "18.10.14.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Connect" -ValueName "RequirePinForPairing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.15.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\CredUI" -ValueName "DisablePasswordReveal" -ExpectedValue 1
Test-RegValue -RecNum "18.10.15.2" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" -ValueName "EnumerateAdministrators" -ExpectedValue 0
Test-RegValue -RecNum "18.10.15.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "NoLocalPasswordResetQuestions" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "DisableOneSettingsDownloads" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "DoNotShowFeedbackNotifications" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "EnableOneSettingsAuditing" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDiagnosticLogCollection" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.7" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\DataCollection" -ValueName "LimitDumpCollection" -ExpectedValue 1
Test-RegValue -RecNum "18.10.16.8" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -ValueName "AllowBuildPreview" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableExperimentalFeatures" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableHashOverride" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableLocalArchiveMalwareScanOverride" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableBypassCertificatePinningForMicrosoftStore" -ExpectedValue 0
Test-RegValue -RecNum "18.10.18.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -ValueName "EnableMSAppInstallerProtocol" -ExpectedValue 0
Test-RegValue -RecNum "18.10.26.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.26.2.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.2.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" -ValueName "MaxSize" -ExpectedValue 196608
Test-RegValue -RecNum "18.10.26.3.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.3.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.26.4.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "Retention" -ExpectedValue "0"
Test-RegValue -RecNum "18.10.26.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\EventLog\System" -ValueName "MaxSize" -ExpectedValue 32768
Test-RegValue -RecNum "18.10.29.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Explorer" -ValueName "DisableMotWOnInsecurePathCopy" -ExpectedValue 0
Test-RegValue -RecNum "18.10.29.5" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "PreXPSP2ShellProtocolBehavior" -ExpectedValue 0
Test-RegValue -RecNum "18.10.35.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -ValueName "NotifyDisableIEOptions" -ExpectedValue 0
Test-RegValue -RecNum "18.10.58.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "DisableEnclosureDownload" -ExpectedValue 1
Test-RegValue -RecNum "18.10.58.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" -ValueName "AllowBasicAuthInClear" -ExpectedValue 0
Test-RegValue -RecNum "18.10.43.11.1.1.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection" -ValueName "BruteForceProtectionConfiguredState" -ExpectedValue 2
Test-RegValue -RecNum "18.10.43.13.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -ValueName "DisablePackedExeScanning" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortana" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.4" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowCortanaAboveLock" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.5" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowIndexingEncryptedStoresOrItems" -ExpectedValue 0
Test-RegValue -RecNum "18.10.59.6" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Windows Search" -ValueName "AllowSearchToUseLocation" -ExpectedValue 0
Test-RegValue -RecNum "18.10.66.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "AutoDownload" -ExpectedValue 4
Test-RegValue -RecNum "18.10.66.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\WindowsStore" -ValueName "DisableOSUpgrade" -ExpectedValue 1
Test-RegValue -RecNum "18.10.72.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Dsh" -ValueName "AllowNewsAndInterests" -ExpectedValue 0
Test-RegValue -RecNum "18.10.82.1" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableMPR" -ExpectedValue 0
Test-RegValue -RecNum "18.10.82.2" -Hive "HKLM" -KeyPath "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DisableAutomaticRestartSignOn" -ExpectedValue 1
Test-RegValue -RecNum "18.10.91.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Sandbox" -ValueName "AllowClipboardRedirection" -ExpectedValue 0
Test-RegValue -RecNum "18.10.91.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\Sandbox" -ValueName "AllowNetworking" -ExpectedValue 0
Test-RegValue -RecNum "18.10.93.2.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "SetDisablePauseUXAccess" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "ManagePreviewBuildsPolicyValue" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferFeatureUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.4.3" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ValueName "DeferQualityUpdates" -ExpectedValue 1
Test-RegValue -RecNum "18.10.93.2.2" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "ScheduledInstallDay" -ExpectedValue 0
Test-RegValue -RecNum "18.10.93.1.1" -Hive "HKLM" -KeyPath "SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -ExpectedValue 0

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
