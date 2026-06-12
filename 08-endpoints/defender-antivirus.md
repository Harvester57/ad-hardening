# Hardening Requirement: Windows Defender Antivirus Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
  * Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection
  * Computer Configuration\Preferences\Windows Settings\Environment
  * HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
  * HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR
  * HKLM\SOFTWARE\Microsoft\Windows Defender\Features
  * HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment

---

## Rationale
Windows Defender Antivirus is the primary endpoint protection suite on Windows platforms. To establish a robust defense-in-depth posture against modern endpoint threat vectors, the basic protection must be augmented with Exploit Guard, Tamper Protection, and process isolation.

This control introduces three primary hardening mechanisms:
1. **Attack Surface Reduction (ASR) Rules**: Restricts behaviors commonly exploited by malware. By blocking the execution of obfuscated scripts, restricting child process creation from Office/Adobe products, protecting the LSASS process from credential dumping, and limiting unsafe process execution from USB drives, ASR severely curtails the initial access and lateral movement capabilities of threat actors.
2. **Tamper Protection**: Secures the Defender Antivirus services and registry keys. Without this control, an administrative account compromised via lateral movement could disable Defender or add exclusions to permit payload execution.
3. **Sandbox Execution (AppContainer)**: Forces the Defender service (MsMpEng.exe) to run in a restricted AppContainer sandbox. Since antimalware engines parse untrusted, potentially malicious file structures, a zero-day vulnerability in the parsing engine could lead to system compromise. Sandbox execution mitigates this by containing any exploit inside the AppContainer, preventing privilege escalation.

---

## Legacy Impact & Compatibility
* **ASR Administrative Impact**: Enabling ASR rules can block legacy administrative scripts or third-party orchestration tools that rely on WMI/PSExec or execute obfuscated administrative wrappers. Extensive audit testing is recommended prior to broad enforcement.
* **Office Application Rules**: Rules related to Microsoft Office (e.g., blocking child processes) apply only to endpoints where productivity suites are installed. They will have no impact on member servers without Office.
* **Sandbox Boot Overhead**: Setting `MP_FORCE_USE_SANDBOX` requires a reboot to initialize the scanning process within the AppContainer sandbox. There is negligible performance overhead once initialized.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
4. Configure the following settings:
   * **Policy**: `Turn off Windows Defender Antivirus`
   * **Setting**: `Disabled` (ensures Defender is active)
5. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection`
6. Configure the following settings:
   * **Policy**: `Turn off real-time protection`
   * **Setting**: `Disabled`
   * **Policy**: `Turn on behavior monitoring`
   * **Setting**: `Enabled`
   * **Policy**: `Scan all downloaded files and attachments`
   * **Setting**: `Enabled`
7. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Exclusions`
8. Configure the setting:
   * **Policy**: `Prevent users from configuring exclusions`
   * **Setting**: `Enabled`
9. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS`
10. Configure the following settings:
    * **Policy**: `Join Microsoft MAPS`
    * **Setting**: `Enabled` (Select `Advanced MAPS` in options)
    * **Policy**: `Send file samples when further analysis is required`
    * **Setting**: `Enabled` (Select `Send safe samples` in options)
11. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MpEngine`
12. Configure the setting:
    * **Policy**: `Select cloud protection level`
    * **Setting**: `Enabled` (Select `High blocking level` in options)
13. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan`
14. Configure the setting:
    * **Policy**: `Scan removable drives`
    * **Setting**: `Enabled`
15. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection`
16. Configure the setting:
    * **Policy**: `Prevent users and apps from accessing dangerous websites`
    * **Setting**: `Enabled` (Select `Block` in options)
17. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
18. Configure the setting:
    * **Policy**: `Configure detection for potentially unwanted applications`
    * **Setting**: `Enabled` (Select `Block` in options)
19. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
20. Configure the setting:
    * **Policy**: `Configure Attack Surface Reduction rules`
    * **Setting**: `Enabled`
    * Click **Show...** and enter the following GUIDs as Value Names, with Value set to `1` (Block):
      * `56a863a9-875e-4185-98a7-b882c64b5ce5` (Block abuse of exploited vulnerable signed drivers)
      * `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` (Block Adobe Reader from creating child processes)
      * `d4f940ab-401b-4efc-aadc-ad5f3c50688a` (Block all Office applications from creating child processes)
      * `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from the Windows Local Security Authority subsystem)
      * `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` (Block executable content from email client and webmail)
      * `01443614-cd74-433a-b99e-2ecdc7777d85` (Block executable files from running unless they meet a prevalence, age, or trusted list criterion)
      * `5beb7efe-fd9a-4556-801d-275e5ffc04cc` (Block execution of potentially obfuscated scripts)
      * `d3e037e1-3eb8-44c8-a917-57927947596d` (Block JavaScript or VBScript from launching downloaded executable content)
      * `3b576869-a4ec-4529-8536-b80a7769e899` (Block Office applications from creating executable content)
      * `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` (Block Office applications from injecting code into other processes)
      * `26190899-1602-49e8-8b27-eb1d0a1ce869` (Block Office communication application from creating child processes)
      * `e6db77e5-3df2-4cf1-b95a-636979351e5b` (Block persistence through WMI event subscription)
      * `d1e49aac-8f56-4280-b9ba-993a6d77406c` (Block process creations originating from PSExec and WMI commands)
      * `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` (Block untrusted and unsigned processes that run from USB)
      * `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` (Block Win32 API calls from Office macros)
      * `c1db55ab-c21a-4637-bb3f-a12568109d35` (Use advanced protection against ransomware)
11. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection`
12. Configure the setting:
    * **Policy**: `Protect Windows Security settings from tampering`
    * **Setting**: `Enabled` (Select **Block** or **On** depending on ADMX version)
13. Navigate to:
    `Computer Configuration\Preferences\Windows Settings\Environment`
14. Right-click **Environment**, select **New -> Environment Variable**.
15. Configure the following properties:
    * **Action**: `Update`
    * **Type**: `System`
    * **Name**: `MP_FORCE_USE_SANDBOX`
    * **Value**: `1`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure Windows Defender baseline protection, Attack Surface Reduction rules, Tamper Protection, and Sandbox execution.

[Download Script: Set-DefenderAdvancedBaseline.ps1](implementation_scripts/Set-DefenderAdvancedBaseline.ps1)

```powershell
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
```

*To audit the Windows Defender advanced hardening status:*
[Download Script: Get-DefenderAdvancedStatus.ps1](audit_scripts/Get-DefenderAdvancedStatus.ps1)

```powershell
# Get-DefenderAdvancedStatus.ps1
# Description: Audits the registry and preferences for ASR, Tamper Protection, and Sandbox status.

Write-Host "--- Auditing Windows Defender Advanced Hardening Status ---" -ForegroundColor Cyan

# 1. Audit core preferences
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $Pref = Get-MpPreference
    
    $RealtimeColor = if ($Pref.DisableRealtimeMonitoring -eq $false) { "Green" } else { "Red" }
    $BehaviorColor = if ($Pref.DisableBehaviorMonitoring -eq $false) { "Green" } else { "Red" }
    $ExclColor = if ($Pref.DisableLocalAdminConfiguration -eq 1 -or $Pref.DisableLocalAdminConfiguration -eq $true) { "Green" } else { "Red" }
    $MapsColor = if ($Pref.MAPSReporting -eq 2) { "Green" } else { "Red" }
    $SamplesColor = if ($Pref.SubmitSamplesConsent -eq 1) { "Green" } else { "Red" }
    $CloudColor = if ($Pref.MpCloudBlockLevel -eq 2) { "Green" } else { "Red" }
    $RemovableColor = if ($Pref.DisableRemovableDriveScanning -eq $false) { "Green" } else { "Red" }
    $NetProtColor = if ($Pref.EnableNetworkProtection -eq 1 -or $Pref.EnableNetworkProtection -eq $true) { "Green" } else { "Red" }
    $PuaColor = if ($Pref.PUAProtection -eq 1) { "Green" } else { "Red" }
    
    Write-Host "    - Real-Time Monitoring Active: $(!$Pref.DisableRealtimeMonitoring) (Required: True)" -ForegroundColor $RealtimeColor
    Write-Host "    - Behavior Monitoring Active: $(!$Pref.DisableBehaviorMonitoring) (Required: True)" -ForegroundColor $BehaviorColor
    Write-Host "    - Exclusions Blocked: $($Pref.DisableLocalAdminConfiguration) (Required: True)" -ForegroundColor $ExclColor
    Write-Host "    - MAPS Reporting (Advanced): $($Pref.MAPSReporting) (Required: 2)" -ForegroundColor $MapsColor
    Write-Host "    - Submit Samples (Safe): $($Pref.SubmitSamplesConsent) (Required: 1)" -ForegroundColor $SamplesColor
    Write-Host "    - Cloud Protection Level: $($Pref.MpCloudBlockLevel) (Required: 2)" -ForegroundColor $CloudColor
    Write-Host "    - Removable Drive Scanning: $(!$Pref.DisableRemovableDriveScanning) (Required: True)" -ForegroundColor $RemovableColor
    Write-Host "    - Network Protection: $($Pref.EnableNetworkProtection) (Required: 1)" -ForegroundColor $NetProtColor
    Write-Host "    - PUA Protection: $($Pref.PUAProtection) (Required: 1)" -ForegroundColor $PuaColor
} else {
    Write-Warning "Get-MpPreference is not available."
}

# 2. Audit Sandbox variable
$EnvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$SandboxVar = Get-ItemProperty -Path $EnvPath -Name "MP_FORCE_USE_SANDBOX" -ErrorAction SilentlyContinue
if ($SandboxVar -and $SandboxVar.MP_FORCE_USE_SANDBOX -eq "1") {
    Write-Host "    - Sandbox Execution: Enabled (MP_FORCE_USE_SANDBOX = 1)" -ForegroundColor Green
} else {
    Write-Host "    - Sandbox Execution: NOT ENABLED (Required: 1)" -ForegroundColor Red
}

# 3. Audit Tamper Protection registry
$FeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
$TamperVal = Get-ItemProperty -Path $FeaturesPath -Name "TamperProtection" -ErrorAction SilentlyContinue
if ($TamperVal -and $TamperVal.TamperProtection -eq 5) {
    Write-Host "    - Tamper Protection: Enabled (TamperProtection = 5)" -ForegroundColor Green
} else {
    Write-Host "    - Tamper Protection: NOT ENABLED or Not Managed via local Registry (Value: $($TamperVal.TamperProtection))" -ForegroundColor Yellow
}

# 4. Audit ASR Rules
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
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
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9.47 (Exclusions restrictions), Section 18.9.30 (ASR Rules), Section 18.9.47.11 (Real-time protection)
* **Microsoft Security Baselines**: Windows Defender Exploit Guard deployment guide
* **ANSSI Active Directory Hardening Guide**: Recommendations regarding endpoint protective controls
