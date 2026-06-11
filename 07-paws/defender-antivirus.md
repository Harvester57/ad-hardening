# Hardening Requirement: Windows Defender Antivirus PAW Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) represent the highest security boundary on the endpoint layer, serving as isolated systems dedicated solely to Tier 0 directory administration. If a PAW is compromised, the entire AD forest is compromised. Therefore, the built-in antimalware and exploit prevention controls must be hardened to their absolute maximum threshold.

This control introduces a highly restrictive protective barrier on PAWs:
1. **Attack Surface Reduction (ASR) Rules**: ASR rules block activities commonly used by threat actors to perform remote execution, persistence, and credential theft. On PAWs, all rules are configured to strict Block mode. Crucially, rules blocking LSASS credential stealing (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) and WMI/PSExec child process creation (`d1e49fe6-3b60-4270-a130-058b290d024a`) are enforced. Since PAWs are reserved for administrative consoles and not daily use software, there is a lower threat of user-facing disruption.
2. **Tamper Protection**: Restricts any software or unauthorized administrator from disabling real-time scanning, cloud components, behavior monitoring, or exclusions. This blocks malicious actors from trying to disable security controls if they gain command execution.
3. **Sandbox Execution (AppContainer)**: Sandboxes the core scanning service (`MsMpEng.exe`). If an attacker attempts to exploit a parser flaw in the Defender engine itself using a specifically crafted malicious file, the exploit is restricted to the AppContainer sandbox, mitigating privilege escalation on Tier 0 assets.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Enabling the WMI/PSExec block rule means administrative scripts must be run locally or orchestrated via secure WinRM endpoints. Traditional PSExec commands from remote management consoles will be blocked, enforcing proper tier-isolated remote administration.
* **Execution Restrictions**: Since productivity suites (e.g., Office, Outlook) are strictly banned from PAWs, ASR rules targeting Microsoft Office applications are enforced as a defensive measure to prevent shadow installations or bypasses.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the PAWs OU (e.g., `GPO_Hardening_PAW`).
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
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
10. Configure the setting:
    * **Policy**: `Configure Attack Surface Reduction rules`
    * **Setting**: `Enabled`
    * Click **Show...** and enter the following GUIDs as Value Names, with Value set to `1` (Block):
      * `56a863a9-875e-4185-98a7-b942c6b2d340` (Block abuse of exploited vulnerable signed drivers)
      * `7674ba7d-e6d2-4350-9d58-7c1dbb33e758` (Block Adobe Reader from creating child processes)
      * `d4f940ab-401b-4efc-aadc-ad5f3c50688a` (Block all Office applications from creating child processes)
      * `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from the Windows Local Security Authority subsystem)
      * `be9ba2d9-53ea-4d1e-8a57-ab6b53dbb5c5` (Block executable content from email client and webmail)
      * `01443614-cd74-433a-b99e-2ecdc7777d85` (Block executable files from running unless they meet a prevalence, age, or trusted list criterion)
      * `5beb7efe-fd9a-4556-801d-275e5ffc04cc` (Block execution of potentially obfuscated scripts)
      * `d3e03999-47ed-4e2a-8747-0d41b5906d20` (Block JavaScript or VBScript from launching downloaded executable content)
      * `3b576869-74b4-40f2-aa33-a652e742e285` (Block Office applications from creating executable content)
      * `75668c1f-73b5-4cf0-bb9c-a86f45a22650` (Block Office applications from injecting code into other processes)
      * `261908b1-1602-4977-800c-d10d9d93d34f` (Block Office communication application from creating child processes)
      * `e1105574-81d5-4b0c-8a1e-8793133d82e9` (Block persistence through WMI event subscription)
      * `d1e49fe6-3b60-4270-a130-058b290d024a` (Block process creations originating from PSExec and WMI commands)
      * `b2b3f03d-fd1f-4654-8491-64d549174092` (Block untrusted and unsigned processes that run from USB)
      * `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` (Block Win32 API calls from Office macros)
      * `c1db55ab-c21a-4637-bb3f-a125b2061d5d` (Use advanced protection against ransomware)
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

Run the following scripts locally on the PAW to configure Windows Defender baseline, ASR rules, Tamper Protection, and Sandbox execution.

```powershell
# Set-DefenderPawBaseline.ps1
# Description: Configures Windows Defender Antivirus options, ASR rules, Tamper Protection, and Sandbox execution on PAWs.

Write-Host "Applying Windows Defender PAW Hardening Baseline..." -ForegroundColor Cyan

# 1. Core Defender settings
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "Configuring baseline Defender parameters..." -ForegroundColor Gray
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    Set-MpPreference -DisableBlockAtFirstSeen $true
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
    "56a863a9-875e-4185-98a7-b942c6b2d340" = "1"
    "7674ba7d-e6d2-4350-9d58-7c1dbb33e758" = "1"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "1"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "1"
    "be9ba2d9-53ea-4d1e-8a57-ab6b53dbb5c5" = "1"
    "01443614-cd74-433a-b99e-2ecdc7777d85" = "1"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "1"
    "d3e03999-47ed-4e2a-8747-0d41b5906d20" = "1"
    "3b576869-74b4-40f2-aa33-a652e742e285" = "1"
    "75668c1f-73b5-4cf0-bb9c-a86f45a22650" = "1"
    "261908b1-1602-4977-800c-d10d9d93d34f" = "1"
    "e1105574-81d5-4b0c-8a1e-8793133d82e9" = "1"
    "d1e49fe6-3b60-4270-a130-058b290d024a" = "1"
    "b2b3f03d-fd1f-4654-8491-64d549174092" = "1"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "1"
    "c1db55ab-c21a-4637-bb3f-a125b2061d5d" = "1"
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

Write-Host "Defender PAW baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
```

*To audit the local PAW Windows Defender security status:*
```powershell
# Get-DefenderPawStatus.ps1
# Description: Audits the registry and preferences for ASR, Tamper Protection, and Sandbox status on PAWs.

Write-Host "--- Auditing PAW Windows Defender Hardening Status ---" -ForegroundColor Cyan

# 1. Audit core preferences
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $Pref = Get-MpPreference
    
    $RealtimeColor = if ($Pref.DisableRealtimeMonitoring -eq $false) { "Green" } else { "Red" }
    $BehaviorColor = if ($Pref.DisableBehaviorMonitoring -eq $false) { "Green" } else { "Red" }
    $ExclColor = if ($Pref.DisableLocalAdminConfiguration -eq 1 -or $Pref.DisableLocalAdminConfiguration -eq $true) { "Green" } else { "Red" }
    
    Write-Host "    - Real-Time Monitoring Active: $(!$Pref.DisableRealtimeMonitoring) (Required: True)" -ForegroundColor $RealtimeColor
    Write-Host "    - Behavior Monitoring Active: $(!$Pref.DisableBehaviorMonitoring) (Required: True)" -ForegroundColor $BehaviorColor
    Write-Host "    - Exclusions Blocked: $($Pref.DisableLocalAdminConfiguration) (Required: True)" -ForegroundColor $ExclColor
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.9.47 (Exclusions restrictions), Section 18.9.30 (ASR Rules), Section 18.9.47.11 (Real-time protection)
* **ANSSI Active Directory Hardening Guide**: Recommendations regarding administrative workstation isolation and endpoint agent security
