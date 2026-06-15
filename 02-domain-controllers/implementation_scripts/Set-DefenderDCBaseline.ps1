# Set-DefenderDCBaseline.ps1
# Description: Configures Windows Defender Antivirus options, ASR rules, Tamper Protection, and Sandbox execution on DCs.

Write-Host "Applying Windows Defender Domain Controller Baseline..." -ForegroundColor Cyan

# 1. Core Defender settings
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "Configuring baseline Defender parameters..." -ForegroundColor Gray
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -EnableNetworkProtection 1
    Set-MpPreference -DisableExclusionRestriction $false
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -DisableLocalAdminMerge $true
    Set-MpPreference -EnableFileHashComputation $true
    Set-MpPreference -DisablePackedExeScanning $false
    Set-MpPreference -DisableEmailScanning $false
    Set-MpPreference -DisableHeuristics $false
    Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 0 -ErrorAction SilentlyContinue
    Set-MpPreference -BruteForceProtectionAggressiveness 1 -ErrorAction SilentlyContinue
    Set-MpPreference -RemoteEncryptionProtectionAggressiveness 1 -ErrorAction SilentlyContinue
} else {
    Write-Warning "Set-MpPreference cmdlet is not available."
}

# 2. Configure Exclusion restrictions and Local Merges in Registry
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $DefenderPath)) {
    New-Item -Path $DefenderPath -Force | Out-Null
}
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 0 -Type DWord
Set-ItemProperty -Path $DefenderPath -Name "PUAProtection" -Value 1 -Type DWord
Set-ItemProperty -Path $DefenderPath -Name "DisableLocalAdminMerge" -Value 1 -Type DWord
Set-ItemProperty -Path $DefenderPath -Name "HideExclusionsFromLocalAdmins" -Value 1 -Type DWord
Set-ItemProperty -Path $DefenderPath -Name "RandomizeScheduleTaskTimes" -Value 1 -Type DWord

$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) {
    New-Item -Path $ExclPath -Force | Out-Null
}
Set-ItemProperty -Path $ExclPath -Name "DisableLocalAdminConfiguration" -Value 1 -Type DWord
Set-ItemProperty -Path $ExclPath -Name "DisableAutoExclusions" -Value 0 -Type DWord

# 3. Configure NIS, Reporting, Engine, and Scan Settings in Registry
$FeaturesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) {
    New-Item -Path $FeaturesPath -Force | Out-Null
}
Set-ItemProperty -Path $FeaturesPath -Name "PassiveRemediation" -Value 1 -Type DWord

$NetProtPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection"
if (-not (Test-Path $NetProtPath)) {
    New-Item -Path $NetProtPath -Force | Out-Null
}
Set-ItemProperty -Path $NetProtPath -Name "AllowNetworkProtectionOnWinServer" -Value 1 -Type DWord

$MpEnginePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if (-not (Test-Path $MpEnginePath)) {
    New-Item -Path $MpEnginePath -Force | Out-Null
}
Set-ItemProperty -Path $MpEnginePath -Name "EnableFileHashComputation" -Value 1 -Type DWord

$NisPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS"
if (-not (Test-Path $NisPath)) {
    New-Item -Path $NisPath -Force | Out-Null
}
Set-ItemProperty -Path $NisPath -Name "EnableConvertWarnToBlock" -Value 1 -Type DWord
Set-ItemProperty -Path $NisPath -Name "AllowSwitchToAsyncInspection" -Value 1 -Type DWord

$RtpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if (-not (Test-Path $RtpPath)) {
    New-Item -Path $RtpPath -Force | Out-Null
}
Set-ItemProperty -Path $RtpPath -Name "OobeEnableRtpAndSigUpdate" -Value 1 -Type DWord

$RepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if (-not (Test-Path $RepPath)) {
    New-Item -Path $RepPath -Force | Out-Null
}
Set-ItemProperty -Path $RepPath -Name "EnableDynamicSignatureDroppedEventReporting" -Value 1 -Type DWord
Set-ItemProperty -Path $RepPath -Name "DisableGenericRePorts" -Value 1 -Type DWord

$SpynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (-not (Test-Path $SpynetPath)) {
    New-Item -Path $SpynetPath -Force | Out-Null
}
Set-ItemProperty -Path $SpynetPath -Name "SpynetReporting" -Value 0 -Type DWord

$BrutePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection"
if (-not (Test-Path $BrutePath)) {
    New-Item -Path $BrutePath -Force | Out-Null
}
Set-ItemProperty -Path $BrutePath -Name "BruteForceProtectionAggressiveness" -Value 1 -Type DWord

$EncryptPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection"
if (-not (Test-Path $EncryptPath)) {
    New-Item -Path $EncryptPath -Force | Out-Null
}
Set-ItemProperty -Path $EncryptPath -Name "RemoteEncryptionProtectionAggressiveness" -Value 1 -Type DWord

$ScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if (-not (Test-Path $ScanPath)) {
    New-Item -Path $ScanPath -Force | Out-Null
}
Set-ItemProperty -Path $ScanPath -Name "QuickScanIncludeExclusions" -Value 1 -Type DWord
Set-ItemProperty -Path $ScanPath -Name "DisablePackedExeScanning" -Value 0 -Type DWord
Set-ItemProperty -Path $ScanPath -Name "ScheduleDay" -Value 0 -Type DWord
Set-ItemProperty -Path $ScanPath -Name "DisableEmailScanning" -Value 0 -Type DWord
Set-ItemProperty -Path $ScanPath -Name "DisableHeuristics" -Value 0 -Type DWord

$SigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
if (-not (Test-Path $SigPath)) {
    New-Item -Path $SigPath -Force | Out-Null
}
Set-ItemProperty -Path $SigPath -Name "ASSignatureDue" -Value 7 -Type DWord
Set-ItemProperty -Path $SigPath -Name "AVSignatureDue" -Value 7 -Type DWord
Set-ItemProperty -Path $SigPath -Name "ScheduleDay" -Value 0 -Type DWord

# 4. Configure Server-Compatible ASR Rules in Registry
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) {
    New-Item -Path $AsrRulesPath -Force | Out-Null
}

$AsrRules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "1" # Block vulnerable signed drivers
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "1" # Block LSASS credential theft
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "1" # Block obfuscated scripts
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "1" # Block WMI persistence
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "2" # Audit PSExec and WMI process creation (Audit to prevent DC admin tool disruption)
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "1" # Use advanced protection against ransomware
}

foreach ($RuleId in $AsrRules.Keys) {
    $ActionValue = $AsrRules[$RuleId]
    Set-ItemProperty -Path $AsrRulesPath -Name $RuleId -Value $ActionValue -Type String
}
Write-Host "ASR rules configured in registry." -ForegroundColor Green

# 5. Configure Threat severity default quarantine actions
$ThreatsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats"
if (-not (Test-Path $ThreatsPath)) {
    New-Item -Path $ThreatsPath -Force | Out-Null
}
Set-ItemProperty -Path $ThreatsPath -Name "Threats_ThreatSeverityDefaultAction" -Value 1 -Type DWord

$ThreatsSevPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction"
if (-not (Test-Path $ThreatsSevPath)) {
    New-Item -Path $ThreatsSevPath -Force | Out-Null
}
Set-ItemProperty -Path $ThreatsSevPath -Name "1" -Value 2 -Type DWord
Set-ItemProperty -Path $ThreatsSevPath -Name "2" -Value 2 -Type DWord
Set-ItemProperty -Path $ThreatsSevPath -Name "4" -Value 2 -Type DWord
Set-ItemProperty -Path $ThreatsSevPath -Name "5" -Value 2 -Type DWord

$FamilyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options"
if (-not (Test-Path $FamilyPath)) {
    New-Item -Path $FamilyPath -Force | Out-Null
}
Set-ItemProperty -Path $FamilyPath -Name "UILockdown" -Value 1 -Type DWord

# 6. Configure Tamper Protection in Registry
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) {
    New-Item -Path $FeaturesPath -Force | Out-Null
}
try {
    Set-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -Value 5 -Type DWord -ErrorAction Stop
    Write-Host "Tamper Protection enabled in registry." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set Tamper Protection in registry. Access is typically restricted to TrustedInstaller. Use GPO or Defender portal management."
}

# 7. Configure Sandbox Execution Environment Variable
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
if (-not (Test-Path $EnvPath)) {
    New-Item -Path $EnvPath -Force | Out-Null
}
Set-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -Value "1" -Type String
Write-Host "Sandbox Execution environment variable configured." -ForegroundColor Green

# 8. Configure AMSI Authenticode Signature Verification (FeatureBits = 2)
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (-not (Test-Path $AmsiPath)) {
    New-Item -Path $AmsiPath -Force | Out-Null
}
Set-ItemProperty -Path $AmsiPath -Name "FeatureBits" -Value 2 -Type DWord -Force
Write-Host "[+] AMSI Authenticode signature verification enabled." -ForegroundColor Green

Write-Host "Defender Domain Controller baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
