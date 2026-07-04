# [REQ-END-007] Windows Defender Antivirus Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
    * `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
    * `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection`
    * `Computer Configuration\Administrative Templates\Windows Components\File Explorer`
  * **Registry Locations**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `DisableAntiSpyware` = `0` (REG_DWORD)
      * `PUAProtection` = `1` (REG_DWORD)
      * `DisableLocalAdminMerge` = `1` (REG_DWORD)
      * `HideExclusionsFromLocalAdmins` = `1` (REG_DWORD)
      * `RandomizeScheduleTaskTimes` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`
      * `DisableLocalAdminConfiguration` = `1` (REG_DWORD)
      * `DisableAutoExclusions` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
      * `LocalSettingOverrideSpynetReporting` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features`
      * `PassiveRemediation` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection`
      * `AllowNetworkProtectionOnWinServer` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine`
      * `EnableFileHashComputation` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS`
      * `EnableConvertWarnToBlock` = `1` (REG_DWORD)
      * `AllowSwitchToAsyncInspection` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `OobeEnableRtpAndSigUpdate` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting`
      * `EnableDynamicSignatureDroppedEventReporting` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `QuickScanIncludeExclusions` = `1` (REG_DWORD)
      * `DisablePackedExeScanning` = `0` (REG_DWORD)
      * `ScheduleDay` = `0` (REG_DWORD)
      * `DisableEmailScanning` = `0` (REG_DWORD)
      * `DisableHeuristics` = `0` (REG_DWORD)
      * `DaysWithoutCatchupQuickScan` = `7` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`
      * `ASSignatureDue` = `7` (REG_DWORD)
      * `AVSignatureDue` = `7` (REG_DWORD)
      * `ScheduleDay` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
      * `56a863a9-875e-4185-98a7-b882c64b5ce5` = `1` (REG_SZ)
      * `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` = `1` (REG_SZ)
      * `d4f940ab-401b-4efc-aadc-ad5f3c50688a` = `1` (REG_SZ)
      * `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` = `1` (REG_SZ)
      * `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` = `1` (REG_SZ)
      * `01443614-cd74-433a-b99e-2ecdc07bfc25` = `1` (REG_SZ)
      * `5beb7efe-fd9a-4556-801d-275e5ffc04cc` = `1` (REG_SZ)
      * `d3e037e1-3eb8-44c8-a917-57927947596d` = `1` (REG_SZ)
      * `3b576869-a4ec-4529-8536-b80a7769e899` = `1` (REG_SZ)
      * `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` = `1` (REG_SZ)
      * `26190899-1602-49e8-8b27-eb1d0a1ce869` = `1` (REG_SZ)
      * `e6db77e5-3df2-4cf1-b95a-636979351e5b` = `1` (REG_SZ)
      * `d1e49aac-8f56-4280-b9ba-993a6d77406c` = `1` (REG_SZ)
      * `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` = `1` (REG_SZ)
      * `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` = `1` (REG_SZ)
      * `c1db55ab-c21a-4637-bb3f-a12568109d35` = `1` (REG_SZ)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats`
      * `Threats_ThreatSeverityDefaultAction` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction`
      * `1` = `2` (REG_DWORD)
      * `2` = `2` (REG_DWORD)
      * `4` = `2` (REG_DWORD)
      * `5` = `2` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options`
      * `UILockdown` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Microsoft\Windows Defender\Features`
      * `TamperProtection` = `5` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
      * `MP_FORCE_USE_SANDBOX` = `1` (REG_SZ)
    * `HKLM\SOFTWARE\Microsoft\AMSI`
      * `FeatureBits` = `2` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `EnableSmartScreen` = `1` (REG_DWORD)
      * `ShellSmartScreenLevel` = `Block` (REG_SZ)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive`
      * `DisableFileSyncNGSC` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`
      * `ScanWithAntiVirus` = `3` (REG_DWORD)

---

## Rationale
Windows Defender Antivirus is the primary endpoint protection suite on Windows platforms. To establish a robust defense-in-depth posture against modern endpoint threat vectors, the basic protection must be augmented with Exploit Guard, Tamper Protection, SmartScreen, and process isolation.

This control introduces four primary hardening mechanisms:
1. **Attack Surface Reduction (ASR) Rules**: Restricts behaviors commonly exploited by malware. By blocking the execution of obfuscated scripts, restricting child process creation from Office/Adobe products, protecting the LSASS process from credential dumping, and limiting unsafe process execution from USB drives, ASR severely curtails the initial access and lateral movement capabilities of threat actors.
2. **Tamper Protection**: Secures the Defender Antivirus services and registry keys. Without this control, an administrative account compromised via lateral movement could disable Defender or add exclusions to permit payload execution.
3. **Sandbox Execution (AppContainer)**: Forces the Defender service (MsMpEng.exe) to run in a restricted AppContainer sandbox. Since antimalware engines parse untrusted, potentially malicious file structures, a zero-day vulnerability in the parsing engine could lead to system compromise. Sandbox execution mitigates this by containing any exploit inside the AppContainer, preventing privilege escalation.
4. **Windows Defender SmartScreen**: Protects against phishing and malware by warning or blocking users before running unrecognized software or visiting potentially dangerous sites. Enforcing a SmartScreen level of "Block" prevents users from bypassing security warnings and executing unauthorized applications.
5. **AMSI Authenticode Signature Verification (`FeatureBits`)**: The Antimalware Scan Interface (AMSI) allows applications to integrate with the installed antivirus product to scan script content and buffers. Attackers may attempt to register rogue AMSI providers to intercept or bypass scans. Enforcing Authenticode signature checks on registered AMSI providers (`FeatureBits` = `2`) ensures that only signed and trusted AMSI provider DLLs are loaded by applications.

---

## Legacy Impact & Compatibility
* **ASR Administrative Impact**: Enabling ASR rules can block legacy administrative scripts or third-party orchestration tools that rely on WMI/PSExec or execute obfuscated administrative wrappers. Extensive audit testing is recommended prior to broad enforcement.
* **Office Application Rules**: Rules related to Microsoft Office (e.g., blocking child processes) apply only to endpoints where productivity suites are installed. They will have no impact on member servers without Office.
* **Sandbox Boot Overhead**: Setting `MP_FORCE_USE_SANDBOX` requires a reboot to initialize the scanning process within the AppContainer sandbox. There is negligible performance overhead once initialized.
* **SmartScreen Impact**: Standard users will be blocked from launching unrecognized software. Support staff must assist with authorizing internal or uncertified custom business applications.
* **AMSI Provider Signatures**: Any third-party antimalware software that registers itself as an AMSI provider must possess a valid, trusted Authenticode signature. Unsigned or self-signed providers will be blocked from loading.

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
   * **Policy**: `Configure detection for potentially unwanted applications`
     * **Setting**: `Enabled` (Select **Block** in options)
   * **Policy**: `Configure local administrator merge behavior for lists`
     * **Setting**: `Disabled` (prevents local list merging)
   * **Policy**: `Randomize scheduled task times`
     * **Setting**: `Enabled`
5. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection`
6. Configure the following settings:
   * **Policy**: `Turn off real-time protection`
     * **Setting**: `Disabled`
   * **Policy**: `Turn on behavior monitoring`
     * **Setting**: `Enabled`
   * **Policy**: `Scan all downloaded files and attachments`
     * **Setting**: `Enabled`
   * **Policy**: `Turn on script scanning`
     * **Setting**: `Enabled`
   * **Policy**: `Configure real-time protection and Security Intelligence Updates during OOBE`
     * **Setting**: `Enabled`
7. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Exclusions`
8. Configure the following settings:
   * **Policy**: `Prevent users from configuring exclusions`
     * **Setting**: `Enabled`
   * **Policy**: `Control whether exclusions are visible to local users` / `Control whether or not exclusions are visible to Local Admins`
     * **Setting**: `Enabled`
   * **Policy**: `Turn off Auto Exclusions`
     * **Setting**: `Disabled` (ensures automatic exclusions remain active)
9. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Features`
10. Configure the setting:
    * **Policy**: `Enable EDR in block mode`
      * **Setting**: `Enabled`
11. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS`
12. Configure the setting:
    * **Policy**: `Configure local setting override for reporting to Microsoft MAPS`
      * **Setting**: `Disabled`
13. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MpEngine`
14. Configure the setting:
    * **Policy**: `Enable file hash computation feature`
      * **Setting**: `Enabled`
15. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan`
16. Configure the following settings:
    * **Policy**: `Scan removable drives`
      * **Setting**: `Enabled`
    * **Policy**: `Scan excluded files and directories during quick scans`
      * **Setting**: `Enabled`
    * **Policy**: `Turn off scanning of packed executables`
      * **Setting**: `Disabled` (ensures packed files are scanned)
    * **Policy**: `Specify the day of the week to run a scheduled scan`
      * **Setting**: `Enabled` (Select `Every day` or `0` in options)
    * **Policy**: `Turn on e-mail scanning`
      * **Setting**: `Enabled`
    * **Policy**: `Turn on heuristics`
      * **Setting**: `Enabled`
    * **Policy**: `Trigger a quick scan after X days without any scans`
      * **Setting**: `Enabled: 7`
17. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Network Protection`
18. Configure the following settings:
    * **Policy**: `Prevent users and apps from accessing dangerous websites`
      * **Setting**: `Enabled` (Select `Block` in options)
    * **Policy**: `This setting controls whether Network Protection is allowed to be configured into block or audit mode on Windows Server`
      * **Setting**: `Enabled`
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
        * `01443614-cd74-433a-b99e-2ecdc07bfc25` (Block executable files from running unless they meet a prevalence, age, or trusted list criterion)
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
21. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Network Inspection System`
22. Configure the following settings:
    * **Policy**: `Convert warn verdict to block`
      * **Setting**: `Enabled`
    * **Policy**: `Turn on asynchronous inspection`
      * **Setting**: `Enabled`
23. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting`
24. Configure the setting:
    * **Policy**: `Configure whether to report Dynamic Signature dropped events`
      * **Setting**: `Enabled`
25. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Security Intelligence Updates`
26. Configure the following settings:
     * **Policy**: `Define the number of days before spyware security intelligence is considered out of date`
       * **Setting**: `Enabled` (Select `7` days in options)
     * **Policy**: `Define the number of days before virus security intelligence is considered out of date`
       * **Setting**: `Enabled` (Select `7` days in options)
     * **Policy**: `Specify the day of the week to check for security intelligence updates`
       * **Setting**: `Enabled` (Select `Every day` or `0` in options)
27. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Threats`
28. Configure the settings:
     * **Policy**: `Specify threat alert levels at which default action should not be taken when detected`
       * **Setting**: `Enabled`
       * Click **Show...** and enter the following threat levels as Value Names, with Value set to `2` (Quarantine):
         * `1` (Low severity) -> `2`
         * `2` (Medium severity) -> `2`
         * `4` (High severity) -> `2`
         * `5` (Severe severity) -> `2`
29. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Family options`
30. Configure the setting:
     * **Policy**: `Hide the Family options area`
       * **Setting**: `Enabled`
31. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Tamper Protection`
32. Configure the setting:
     * **Policy**: `Protect Windows Security settings from tampering`
       * **Setting**: `Enabled` (Select **Block** or **On** depending on ADMX version)
33. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\OneDrive`
34. Configure the setting:
     * **Policy**: `Prevent the usage of OneDrive for file storage`
       * **Setting**: `Enabled`
35. Navigate to:
    `User Configuration\Administrative Templates\Windows Components\Attachment Manager`
36. Configure the setting:
     * **Policy**: `Notify antivirus programs when opening attachments`
       * **Setting**: `Enabled`
37. Navigate to:
    `Computer Configuration\Preferences\Windows Settings\Environment`
38. Right-click **Environment**, select **New -> Environment Variable**.
39. Configure the following properties:
     * **Action**: `Update`
     * **Type**: `System`
     * **Name**: `MP_FORCE_USE_SANDBOX`
     * **Value**: `1`
40. Navigate to:
    `Computer Configuration\Administrative Templates\Windows Components\File Explorer`
41. Configure the following setting:
    * **Policy**: `Configure Windows Defender SmartScreen`
      * **Setting**: `Enabled`
      * **Options**: Select `Require approval from an administrator before running unrecognized software` (forces `ShellSmartScreenLevel` to `Block` and `EnableSmartScreen` to `1`)

#### Step 42: Deploy AMSI Authenticode Verification via GPO Preferences
Since AMSI provider signature verification is not exposed in standard ADMX templates, deploy it via Registry GPO Preferences:
1. Within the endpoints GPO, navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry**, select **New** -> **Registry Item**.
3. Configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SOFTWARE\Microsoft\AMSI`
   * **Value name**: `FeatureBits`
   * **Value type**: `REG_DWORD`
   * **Value data**: `2` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure Windows Defender baseline protection, Attack Surface Reduction rules, Tamper Protection, SmartScreen, and Sandbox execution.

[Download Script: Set-DefenderAdvancedBaseline.ps1](implementation_scripts/Set-DefenderAdvancedBaseline.ps1)

```powershell
# Set-DefenderAdvancedBaseline.ps1
# Configures advanced Windows Defender Antivirus options, ASR rules, Tamper Protection, SmartScreen, and Sandbox execution.

Write-Host "Applying Windows Defender Advanced Baseline..." -ForegroundColor Cyan

# 1. Core Defender settings
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "Configuring baseline Defender parameters..." -ForegroundColor Gray
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableScriptScanning $false
    Set-MpPreference -DisableRemovableDriveScanning $false
    Set-MpPreference -EnableNetworkProtection 1
    Set-MpPreference -PUAProtection 1
    Set-MpPreference -DisableExclusionRestriction $false
    Set-MpPreference -DisableLocalAdminMerge $true
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

# 2b. Configure MAPS local setting override prevention in Registry
$SpynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (-not (Test-Path $SpynetPath)) {
    New-Item -Path $SpynetPath -Force | Out-Null
}
Set-ItemProperty -Path $SpynetPath -Name "LocalSettingOverrideSpynetReporting" -Value 0 -Type DWord -Force

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
Set-ItemProperty -Path $ScanPath -Name "DaysWithoutCatchupQuickScan" -Value 7 -Type DWord -Force

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

# 9. Configure AMSI Authenticode Signature Verification (FeatureBits = 2)
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (-not (Test-Path $AmsiPath)) {
    New-Item -Path $AmsiPath -Force | Out-Null
}
Set-ItemProperty -Path $AmsiPath -Name "FeatureBits" -Value 2 -Type DWord -Force
Write-Host "[+] AMSI Authenticode signature verification enabled." -ForegroundColor Green

# 10. Prevent OneDrive usage
$OneDrivePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $OneDrivePath)) {
    New-Item -Path $OneDrivePath -Force | Out-Null
}
Set-ItemProperty -Path $OneDrivePath -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
Write-Host "[+] OneDrive file storage disabled in registry." -ForegroundColor Green

# 11. Notify Antivirus on opening attachments
$AttachmentsPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if (-not (Test-Path $AttachmentsPath)) {
    New-Item -Path $AttachmentsPath -Force | Out-Null
}
Set-ItemProperty -Path $AttachmentsPath -Name "ScanWithAntiVirus" -Value 3 -Type DWord -Force
Write-Host "[+] Antivirus notification on opening attachments enabled." -ForegroundColor Green

Write-Host "Defender advanced baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
```

*To audit the Windows Defender advanced hardening status:*
[Download Script: Get-DefenderAdvancedStatus.ps1](audit_scripts/Get-DefenderAdvancedStatus.ps1)

```powershell
# Get-DefenderAdvancedStatus.ps1
# Audits the registry and preferences for ASR, Tamper Protection, SmartScreen, and Sandbox status.

Write-Host "--- Auditing Windows Defender Advanced Hardening Status ---" -ForegroundColor Cyan

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
    Write-Host "    - Tamper Protection: NOT ENABLED or Not Managed via Registry (Value: $($TamperVal.TamperProtection))" -ForegroundColor Yellow
}

# 4. Audit SmartScreen configurations
$SmartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (Test-Path $SmartScreenPath) {
    $EnableSS = Get-ItemProperty -Path $SmartScreenPath -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    $SSLevel = Get-ItemProperty -Path $SmartScreenPath -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue
    
    $EnableSSVal = if ($EnableSS) { $EnableSS.EnableSmartScreen } else { $null }
    $SSLevelVal = if ($SSLevel) { $SSLevel.ShellSmartScreenLevel } else { $null }
    
    $SSColor = if ($EnableSSVal -eq 1 -and $SSLevelVal -eq "Block") { "Green" } else { "Red" }
    Write-Host "    - SmartScreen Enable: $EnableSSVal (Expected: 1) | Level: $SSLevelVal (Expected: Block)" -ForegroundColor $SSColor
} else {
    Write-Host "    - SmartScreen Registry Path does not exist." -ForegroundColor Red
}

# 5. Audit ASR Rules
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

# 6. Audit Registry-based STIG configurations
Write-Host "    - Registry configuration checks:" -ForegroundColor Gray
$DefenderPoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"

$CheckKeys = @{
    "DisableLocalAdminMerge" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "HideExclusionsFromLocalAdmins" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "RandomizeScheduleTaskTimes" = @{ Path = $DefenderPoliciesPath; Expected = 1 }
    "DisableAutoExclusions" = @{ Path = "$DefenderPoliciesPath\Exclusions"; Expected = 0 }
    "PassiveRemediation" = @{ Path = "$DefenderPoliciesPath\Features"; Expected = 1 }
    "AllowNetworkProtectionOnWinServer" = @{ Path = "$DefenderPoliciesPath\Windows Defender Exploit Guard\Network Protection"; Expected = 1 }
    "EnableFileHashComputation" = @{ Path = "$DefenderPoliciesPath\MpEngine"; Expected = 1 }
    "EnableConvertWarnToBlock" = @{ Path = "$DefenderPoliciesPath\NIS"; Expected = 1 }
    "AllowSwitchToAsyncInspection" = @{ Path = "$DefenderPoliciesPath\NIS"; Expected = 1 }
    "OobeEnableRtpAndSigUpdate" = @{ Path = "$DefenderPoliciesPath\Real-Time Protection"; Expected = 1 }
    "EnableDynamicSignatureDroppedEventReporting" = @{ Path = "$DefenderPoliciesPath\Reporting"; Expected = 1 }
    "QuickScanIncludeExclusions" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 1 }
    "DisablePackedExeScanning" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 0 }
    "ScheduleDay" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 0 }
    "DisableEmailScanning" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 0 }
    "DisableHeuristics" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 0 }
    "DaysWithoutCatchupQuickScan" = @{ Path = "$DefenderPoliciesPath\Scan"; Expected = 7 }
    "ASSignatureDue" = @{ Path = "$DefenderPoliciesPath\Signature Updates"; Expected = 7 }
    "AVSignatureDue" = @{ Path = "$DefenderPoliciesPath\Signature Updates"; Expected = 7 }
    "LocalSettingOverrideSpynetReporting" = @{ Path = "$DefenderPoliciesPath\Spynet"; Expected = 0 }
    "Threats_ThreatSeverityDefaultAction" = @{ Path = "$DefenderPoliciesPath\Threats"; Expected = 1 }
    "UILockdown" = @{ Path = "$DefenderPoliciesPath\Windows Defender Security Center\Family options"; Expected = 1 }
    "DisableFileSyncNGSC" = @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"; Expected = 1 }
    "ScanWithAntiVirus" = @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Expected = 3 }
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

# 7. Audit AMSI Authenticode verification
$AmsiPath = "HKLM:\SOFTWARE\Microsoft\AMSI"
if (Test-Path $AmsiPath) {
    $AmsiBits = Get-ItemProperty -Path $AmsiPath -Name "FeatureBits" -ErrorAction SilentlyContinue
    $AmsiVal = if ($AmsiBits) { $AmsiBits.FeatureBits } else { 0 }
    $AmsiColor = if ($AmsiVal -eq 2) { "Green" } else { "Red" }
    Write-Host "    - AMSI Authenticode verification (FeatureBits): $AmsiVal (Expected: 2)" -ForegroundColor $AmsiColor
} else {
    Write-Host "    - AMSI Authenticode verification (FeatureBits): NOT ENABLED" -ForegroundColor Red
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9.47 (Exclusions restrictions), Section 18.9.30 (ASR Rules), Section 18.9.47.11 (Real-time protection)
* **Microsoft Security Baselines**: Windows Defender Exploit Guard deployment guide
* **ANSSI Active Directory Hardening Guide**: Recommendations regarding endpoint protective controls
* **DoD Windows 11 STIG**: Windows Defender SmartScreen file explorer requirements.
