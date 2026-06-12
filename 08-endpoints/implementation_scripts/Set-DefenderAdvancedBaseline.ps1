# Set-DefenderAdvancedBaseline.ps1
# Description: Configures advanced Windows Defender Antivirus options, ASR rules, Tamper Protection, and Sandbox execution.

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
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -EnableNetworkProtection 1
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -DisableExclusionRestriction $false
} else {
    Write-Warning "Set-MpPreference cmdlet is not available."
}

# 2. Configure Exclusion restrictions in Registry
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $DefenderPath)) {
    New-Item -Path $DefenderPath -Force | Out-Null
}
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 0 -Type DWord
Set-ItemProperty -Path $DefenderPath -Name "PUAProtection" -Value 1 -Type DWord

$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) {
    New-Item -Path $ExclPath -Force | Out-Null
}
Set-ItemProperty -Path $ExclPath -Name "DisableLocalAdminConfiguration" -Value 1 -Type DWord

# 3. Configure ASR Rules in Registry
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
    "01443614-cd74-433a-b99e-2ecdc7777d85" = "1"
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
    Set-ItemProperty -Path $AsrRulesPath -Name $RuleId -Value $ActionValue -Type String
}
Write-Host "ASR rules configured in registry." -ForegroundColor Green

# 4. Configure Tamper Protection in Registry
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) {
    New-Item -Path $FeaturesPath -Force | Out-Null
}
# Setting TamperProtection value to 5 (Enabled)
# Note: In production, modifying this key directly requires TrustedInstaller permissions.
try {
    Set-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -Value 5 -Type DWord -ErrorAction Stop
    Write-Host "Tamper Protection enabled in registry." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set Tamper Protection in registry. Access is typically restricted to TrustedInstaller. Use GPO or Defender portal management."
}

# 5. Configure Sandbox Execution Environment Variable
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
if (-not (Test-Path $EnvPath)) {
    New-Item -Path $EnvPath -Force | Out-Null
}
Set-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -Value "1" -Type String
Write-Host "Sandbox Execution environment variable configured." -ForegroundColor Green

Write-Host "Defender advanced baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
