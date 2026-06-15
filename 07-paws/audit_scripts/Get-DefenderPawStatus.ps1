# Get-DefenderPawStatus.ps1
# Description: Audits the registry and preferences for ASR, Tamper Protection, and Sandbox status on PAWs.

Write-Host "--- Auditing PAW Windows Defender Hardening Status ---" -ForegroundColor Cyan

# 1. Audit core preferences
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $Pref = Get-MpPreference
    
    $RealtimeColor = if ($Pref.DisableRealtimeMonitoring -eq $false) { "Green" } else { "Red" }
    $BehaviorColor = if ($Pref.DisableBehaviorMonitoring -eq $false) { "Green" } else { "Red" }
    $ExclColor = if ($Pref.DisableLocalAdminConfiguration -eq 1 -or $Pref.DisableLocalAdminConfiguration -eq $true) { "Green" } else { "Red" }
    $RemovableColor = if ($Pref.DisableRemovableDriveScanning -eq $false) { "Green" } else { "Red" }
    $NetProtColor = if ($Pref.EnableNetworkProtection -eq 1 -or $Pref.EnableNetworkProtection -eq $true) { "Green" } else { "Red" }
    $PuaColor = if ($Pref.PUAProtection -eq 1) { "Green" } else { "Red" }
    $ScriptColor = if ($Pref.DisableScriptScanning -eq $false) { "Green" } else { "Red" }
    
    Write-Host "    - Real-Time Monitoring Active: $(!$Pref.DisableRealtimeMonitoring) (Required: True)" -ForegroundColor $RealtimeColor
    Write-Host "    - Behavior Monitoring Active: $(!$Pref.DisableBehaviorMonitoring) (Required: True)" -ForegroundColor $BehaviorColor
    Write-Host "    - Exclusions Blocked: $($Pref.DisableLocalAdminConfiguration) (Required: True)" -ForegroundColor $ExclColor
    Write-Host "    - Removable Drive Scanning: $(!$Pref.DisableRemovableDriveScanning) (Required: True)" -ForegroundColor $RemovableColor
    Write-Host "    - Network Protection: $($Pref.EnableNetworkProtection) (Required: 1)" -ForegroundColor $NetProtColor
    Write-Host "    - PUA Protection: $($Pref.PUAProtection) (Required: 1)" -ForegroundColor $PuaColor
    Write-Host "    - Script Scanning: $(!$Pref.DisableScriptScanning) (Required: True)" -ForegroundColor $ScriptColor
} else {
    Write-Warning "Get-MpPreference is not available."
}

# 2. Audit Sandbox variable
$EnvPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
$SandboxVar = Get-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -ErrorAction SilentlyContinue
if ($SandboxVar -and $SandboxVar.MP_FORCE_USE_SANDBOX -eq "1") {
    Write-Host "    - Sandbox Execution: Enabled (MP_FORCE_USE_SANDBOX = 1)" -ForegroundColor Green
} else {
    Write-Host "    - Sandbox Execution: NOT ENABLED (Required: 1)" -ForegroundColor Red
}

# 3. Audit Tamper Protection registry
$FeaturesPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Features"
$TamperVal = Get-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -ErrorAction SilentlyContinue
if ($TamperVal -and $TamperVal.TamperProtection -eq 5) {
    Write-Host "    - Tamper Protection: Enabled (TamperProtection = 5)" -ForegroundColor Green
} else {
    Write-Host "    - Tamper Protection: NOT ENABLED or Not Managed via Registry (Value: $($TamperVal.TamperProtection))" -ForegroundColor Yellow
}

# 4. Audit ASR Rules
$AsrRulesPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"
$AsrRulesCount = 0
$AsrBlockedCount = 0

if (Test-Path $AsrRulesPath) {
    $Rules = Get-Item -Path $AsrRulesPath
    foreach ($ValName in $Rules.GetValueNames()) {
        $AsrRulesCount++
        $ValData = $Rules.GetValue($ValName)
        if ($ValData -eq "1" -or $ValData -eq 1) {
            $AsrBlockedCount++
        }
    }
}

$AsrColor = if ($AsrBlockedCount -eq 16) { "Green" } else { "Red" }
Write-Host "    - Attack Surface Reduction: $AsrBlockedCount of 16 rules enforced in Block mode" -ForegroundColor $AsrColor

# 5. Audit Registry-based STIG configurations
Write-Host "    - Registry configuration checks:" -ForegroundColor Gray
$DefenderPoliciesPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"

$CheckKeys = @{
    "DisableLocalAdminMerge" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "HideExclusionsFromLocalAdmins" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "RandomizeScheduleTaskTimes" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "DisableAutoExclusions" = @{ Path = "$DefenderPoliciesPath\\Exclusions"; Expected = 0 }
    "PassiveRemediation" = @{ Path = "$DefenderPoliciesPath\\Features"; Expected = 1 }
    "AllowNetworkProtectionOnWinServer" = @{ Path = "$DefenderPoliciesPath\\Windows Defender Exploit Guard\\Network Protection"; Expected = 1 }
    "EnableFileHashComputation" = @{ Path = "$DefenderPoliciesPath\\MpEngine"; Expected = 1 }
    "EnableConvertWarnToBlock" = @{ Path = "$DefenderPoliciesPath\\NIS"; Expected = 1 }
    "AllowSwitchToAsyncInspection" = @{ Path = "$DefenderPoliciesPath\\NIS"; Expected = 1 }
    "OobeEnableRtpAndSigUpdate" = @{ Path = "$DefenderPoliciesPath\\Real-Time Protection"; Expected = 1 }
    "EnableDynamicSignatureDroppedEventReporting" = @{ Path = "$DefenderPoliciesPath\\Reporting"; Expected = 1 }
    "QuickScanIncludeExclusions" = @{ Path = "$DefenderPoliciesPath\\Scan"; Expected = 1 }
    "DisablePackedExeScanning" = @{ Path = "$DefenderPoliciesPath\\Scan"; Expected = 0 }
    "ScheduleDay" = @{ Path = "$DefenderPoliciesPath\\Scan"; Expected = 0 }
    "DisableEmailScanning" = @{ Path = "$DefenderPoliciesPath\\Scan"; Expected = 0 }
    "DisableHeuristics" = @{ Path = "$DefenderPoliciesPath\\Scan"; Expected = 0 }
    "ASSignatureDue" = @{ Path = "$DefenderPoliciesPath\\Signature Updates"; Expected = 7 }
    "AVSignatureDue" = @{ Path = "$DefenderPoliciesPath\\Signature Updates"; Expected = 7 }
    "Threats_ThreatSeverityDefaultAction" = @{ Path = "$DefenderPoliciesPath\\Threats"; Expected = 1 }
    "UILockdown" = @{ Path = "$DefenderPoliciesPath\\Windows Defender Security Center\\Family options"; Expected = 1 }
}

foreach ($KeyName in $CheckKeys.Keys) {
    $Target = $CheckKeys[$KeyName]
    $Val = Get-ItemProperty -Path $Target.Path -Name $KeyName -ErrorAction SilentlyContinue
    if ($Val -and $Val.$KeyName -eq $Target.Expected) {
        # Validated
    } else {
        $Actual = if ($Val) { $Val.$KeyName } else { "Not Configured" }
        Write-Host "      * Missing/Misconfigured: $KeyName (Expected: $($Target.Expected), Got: $Actual)" -ForegroundColor Yellow
    }
}

# 6. Audit AMSI Authenticode verification
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (Test-Path $AmsiPath) {
    $AmsiBits = Get-ItemProperty -Path $AmsiPath -Name "FeatureBits" -ErrorAction SilentlyContinue
    $AmsiVal = if ($AmsiBits) { $AmsiBits.FeatureBits } else { 0 }
    $AmsiColor = if ($AmsiVal -eq 2) { "Green" } else { "Red" }
    Write-Host "    - AMSI Authenticode verification (FeatureBits): $AmsiVal (Expected: 2)" -ForegroundColor $AmsiColor
} else {
    Write-Host "    - AMSI Authenticode verification (FeatureBits): NOT ENABLED" -ForegroundColor Red
}
