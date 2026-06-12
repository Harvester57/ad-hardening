# Set-DefenderAdvancedBaseline.ps1
# Configures advanced Windows Defender Antivirus options, ASR rules, Tamper Protection, SmartScreen, and Sandbox execution.

Write-Host "Applying Windows Defender Advanced Baseline..." -ForegroundColor Cyan

# 1. Core Defender settings
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "Configuring baseline Defender parameters..." -ForegroundColor Gray
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableBlockAtFirstSeen $false
    Set-MpPreference -MAPSReporting 2
    Set-MpPreference -SubmitSamplesConsent 1
    Set-MpPreference -MpCloudBlockLevel 2
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -EnableNetworkProtection 1
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -DisableExclusionRestriction $false
    Set-MpPreference -DisableLocalAdminMerge $true
    Set-MpPreference -MpBafsExtendedTimeout 50
    Set-MpPreference -EnableFileHashComputation $true
    Set-MpPreference -DisablePackedExeScanning $false
    Set-MpPreference -DisableEmailScanning $false
    Set-MpPreference -DisableHeuristics $false
} else {
    Write-Warning "Set-MpPreference cmdlet is not available."
}

# 2. Configure Exclusion restrictions and Local Merges in Registry
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $DefenderPath)) {
    New-Item -Path $DefenderPath -Force | Out-Null
}
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $DefenderPath -Name "PUAProtection" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $DefenderPath -Name "DisableLocalAdminMerge" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $DefenderPath -Name "HideExclusionsFromLocalAdmins" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $DefenderPath -Name "RandomizeScheduleTaskTimes" -Value 1 -Type DWord -Force

$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) {
    New-Item -Path $ExclPath -Force | Out-Null
}
Set-ItemProperty -Path $ExclPath -Name "DisableLocalAdminConfiguration" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ExclPath -Name "DisableAutoExclusions" -Value 0 -Type DWord -Force

# 3. Configure NIS, Reporting, Engine, and Scan Settings in Registry
$FeaturesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) {
    New-Item -Path $FeaturesPath -Force | Out-Null
}
Set-ItemProperty -Path $FeaturesPath -Name "PassiveRemediation" -Value 1 -Type DWord -Force

$NetProtPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
if (-not (Test-Path $NetProtPath)) {
    New-Item -Path $NetProtPath -Force | Out-Null
}
Set-ItemProperty -Path $NetProtPath -Name "AllowNetworkProtectionOnWinServer" -Value 1 -Type DWord -Force

$MpEnginePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if (-not (Test-Path $MpEnginePath)) {
    New-Item -Path $MpEnginePath -Force | Out-Null
}
Set-ItemProperty -Path $MpEnginePath -Name "MpBafsExtendedTimeout" -Value 50 -Type DWord -Force
Set-ItemProperty -Path $MpEnginePath -Name "EnableFileHashComputation" -Value 1 -Type DWord -Force

$NisPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS"
if (-not (Test-Path $NisPath)) {
    New-Item -Path $NisPath -Force | Out-Null
}
Set-ItemProperty -Path $NisPath -Name "EnableConvertWarnToBlock" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NisPath -Name "AllowSwitchToAsyncInspection" -Value 1 -Type DWord -Force

$RtpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if (-not (Test-Path $RtpPath)) {
    New-Item -Path $RtpPath -Force | Out-Null
}
Set-ItemProperty -Path $RtpPath -Name "OobeEnableRtpAndSigUpdate" -Value 1 -Type DWord -Force

$RepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if (-not (Test-Path $RepPath)) {
    New-Item -Path $RepPath -Force | Out-Null
}
Set-ItemProperty -Path $RepPath -Name "EnableDynamicSignatureDroppedEventReporting" -Value 1 -Type DWord -Force

$ScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if (-not (Test-Path $ScanPath)) {
    New-Item -Path $ScanPath -Force | Out-Null
}
Set-ItemProperty -Path $ScanPath -Name "QuickScanIncludeExclusions" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisablePackedExeScanning" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "ScheduleDay" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableEmailScanning" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableHeuristics" -Value 0 -Type DWord -Force

$SigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
if (-not (Test-Path $SigPath)) {
    New-Item -Path $SigPath -Force | Out-Null
}
Set-ItemProperty -Path $SigPath -Name "ASSignatureDue" -Value 7 -Type DWord -Force
Set-ItemProperty -Path $SigPath -Name "AVSignatureDue" -Value 7 -Type DWord -Force
Set-ItemProperty -Path $SigPath -Name "ScheduleDay" -Value 0 -Type DWord -Force

# 4. Configure ASR Rules in Registry
$AsrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
if (-not (Test-Path $AsrPath)) {
    New-Item -Path $AsrPath -Force | Out-Null
}
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) {
    New-Item -Path $AsrRulesPath -Force | Out-Null
}

$AsrRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "1"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "1"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "1"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "1"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "1"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "1"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "1"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "1"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "1"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "1"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "1"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "1"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "1"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "1"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "1"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "1"
}

foreach ($RuleId in $AsrRules.Keys) {
    $ActionValue = $AsrRules[$RuleId]
    Set-ItemProperty -Path $AsrRulesPath -Name $RuleId -Value $ActionValue -Type String -Force
}
Write-Host "ASR rules configured in registry." -ForegroundColor Green

# 5. Configure Threat severity default quarantine actions
$ThreatsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats"
if (-not (Test-Path $ThreatsPath)) {
    New-Item -Path $ThreatsPath -Force | Out-Null
}
Set-ItemProperty -Path $ThreatsPath -Name "Threats_ThreatSeverityDefaultAction" -Value 1 -Type DWord -Force

$ThreatsSevPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction"
if (-not (Test-Path $ThreatsSevPath)) {
    New-Item -Path $ThreatsSevPath -Force | Out-Null
}
Set-ItemProperty -Path $ThreatsSevPath -Name "1" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "2" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "4" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "5" -Value 2 -Type DWord -Force

$FamilyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options"
if (-not (Test-Path $FamilyPath)) {
    New-Item -Path $FamilyPath -Force | Out-Null
}
Set-ItemProperty -Path $FamilyPath -Name "UILockdown" -Value 1 -Type DWord -Force

# 6. Configure Tamper Protection in Registry
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) {
    New-Item -Path $FeaturesPath -Force | Out-Null
}
try {
    Set-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -Value 5 -Type DWord -ErrorAction Stop -Force
    Write-Host "Tamper Protection enabled in registry." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set Tamper Protection in registry. Access is typically restricted to TrustedInstaller. Use GPO or Defender portal management."
}

# 7. Configure Sandbox Execution Environment Variable
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
if (-not (Test-Path $EnvPath)) {
    New-Item -Path $EnvPath -Force | Out-Null
}
Set-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -Value "1" -Type String -Force
Write-Host "Sandbox Execution environment variable configured." -ForegroundColor Green

# 8. Configure SmartScreen (EnableSmartScreen = 1, ShellSmartScreenLevel = Block)
$SmartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SmartScreenPath)) {
    New-Item -Path $SmartScreenPath -Force | Out-Null
}
Set-ItemProperty -Path $SmartScreenPath -Name "EnableSmartScreen" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $SmartScreenPath -Name "ShellSmartScreenLevel" -Value "Block" -Type String -Force
Write-Host "[+] Windows Defender SmartScreen configured in registry." -ForegroundColor Green

Write-Host "Defender advanced baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
