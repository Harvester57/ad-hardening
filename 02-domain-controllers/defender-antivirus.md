# Hardening Requirement: Windows Defender Antivirus Domain Controller Baseline and Exploit Guard

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

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
Domain Controllers are the most critical assets in an Active Directory environment, containing the Active Directory database (NTDS.dit) and credential material for the entire enterprise. Because Domain Controllers are Tier 0 assets, protective security agents running on them must be hardened to prevent credential access, lateral movement, and tampering.

This control establishes a server-optimized defense posture:
1. **Attack Surface Reduction (ASR) Rules**: Enforces key security boundaries on the OS. Specifically, blocking credential harvesting from LSASS (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`) is paramount on Domain Controllers to prevent offline hash-cracking and token manipulation. In addition, blocking the abuse of exploited vulnerable signed drivers (`56a863a9-875e-4185-98a7-b882c64b5ce5`) blocks kernel-mode exploits, while blocking persistence through WMI event subscriptions (`e6db77e5-3df2-4cf1-b95a-636979351e5b`) mitigates common server stealth mechanisms.
2. **Tamper Protection**: Ensures that attackers cannot use compromised local SYSTEM/admin contexts (such as those obtained via exploit) to disable real-time protection or add exclusions to bypass Defender scanning.
3. **Sandbox Execution (AppContainer)**: Sandboxes the core scanning service (`MsMpEng.exe`). If an attacker attempts to exploit a parsing vulnerability in the antimalware engine (e.g., using a malformed certificate file or replication data), the exploit is restricted to the AppContainer sandbox, mitigating privilege escalation to local system privileges.

---

## Legacy Impact & Compatibility
* **ASR PSExec and WMI Rule**: Enforcing "Block process creations originating from PSExec and WMI commands" (`d1e49aac-8f56-4280-b9ba-993a6d77406c`) can disrupt enterprise remote administration, monitoring agents, and backup orchestrators. In environments utilizing such orchestrators, this rule should be set to **Audit** mode or configured with explicit process exclusions rather than hard Block mode.
* **Office Application Rules**: Rules targeting Microsoft Office or Adobe applications are documented but will not affect Domain Controllers, as these applications must never be installed on Tier 0 systems.
* **Reboot Requirement**: Activating Sandbox Execution via `MP_FORCE_USE_SANDBOX` requires a reboot of the Domain Controllers to take effect. This should be scheduled during standard maintenance windows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
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
   * **Policy**: `Turn on script scanning`
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
    `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
10. Configure the setting:
    * **Policy**: `Configure Attack Surface Reduction rules`
    * **Setting**: `Enabled`
    * Click **Show...** and enter the following GUIDs as Value Names, with Value set to `1` (Block) or `2` (Audit) as detailed:
      * `56a863a9-875e-4185-98a7-b882c64b5ce5` (Block abuse of exploited vulnerable signed drivers) -> `1` (Block)
      * `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` (Block credential stealing from the Windows Local Security Authority subsystem) -> `1` (Block)
      * `5beb7efe-fd9a-4556-801d-275e5ffc04cc` (Block execution of potentially obfuscated scripts) -> `1` (Block)
      * `e6db77e5-3df2-4cf1-b95a-636979351e5b` (Block persistence through WMI event subscription) -> `1` (Block)
      * `d1e49aac-8f56-4280-b9ba-993a6d77406c` (Block process creations originating from PSExec and WMI commands) -> `2` (Audit) (Recommended for DCs to prevent remote management disruptions; configure to `1` only if orchestration is fully migrated to WinRM)
      * `c1db55ab-c21a-4637-bb3f-a12568109d35` (Use advanced protection against ransomware) -> `1` (Block)
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

Run the following scripts locally on the Domain Controller to configure Windows Defender baseline, ASR rules, Tamper Protection, and Sandbox execution.

[Download Script: Set-DefenderDCBaseline.ps1](implementation_scripts/Set-DefenderDCBaseline.ps1)

```powershell
# Set-DefenderDCBaseline.ps1
# Description: Configures Windows Defender Antivirus options, ASR rules, Tamper Protection, and Sandbox execution on DCs.

Write-Host "Applying Windows Defender Domain Controller Baseline..." -ForegroundColor Cyan

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

# 3. Configure Server-Compatible ASR Rules in Registry
$AsrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
if (-not (Test-Path $AsrPath)) {
    New-Item -Path $AsrPath -Force | Out-Null
}
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

Write-Host "Defender Domain Controller baseline configuration completed. A reboot is required to initialize Sandbox Execution." -ForegroundColor Cyan
```

*To audit the local Domain Controller Windows Defender security status:*
[Download Script: Get-DefenderDCStatus.ps1](audit_scripts/Get-DefenderDCStatus.ps1)

```powershell
# Get-DefenderDCStatus.ps1
# Description: Audits the registry and preferences for ASR, Tamper Protection, and Sandbox status on Domain Controllers.

Write-Host "--- Auditing Domain Controller Windows Defender Hardening Status ---" -ForegroundColor Cyan

# 1. Audit core preferences
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $Pref = Get-MpPreference
    
    $RealtimeColor = if ($Pref.DisableRealtimeMonitoring -eq $false) { "Green" } else { "Red" }
    $BehaviorColor = if ($Pref.DisableBehaviorMonitoring -eq $false) { "Green" } else { "Red" }
    $ExclColor = if ($Pref.DisableLocalAdminConfiguration -eq 1 -or $Pref.DisableLocalAdminConfiguration -eq $true) { "Green" } else { "Red" }
    $MapsColor = if ($Pref.MAPSReporting -eq 2) { "Green" } else { "Red" }
    $SamplesColor = if ($Pref.SubmitSamplesConsent -eq 1) { "Green" } else { "Red" }
    $CloudColor = if ($Pref.MpCloudBlockLevel -eq 2) { "Green" } else { "Red" }
    $ScriptColor = if ($Pref.DisableScriptScanning -eq $false) { "Green" } else { "Red" }
    $RemovableColor = if ($Pref.DisableRemovableDriveScanning -eq $false) { "Green" } else { "Red" }
    $NetProtColor = if ($Pref.EnableNetworkProtection -eq 1) { "Green" } else { "Red" }
    
    Write-Host "    - Real-Time Monitoring Active: $(!$Pref.DisableRealtimeMonitoring) (Required: True)" -ForegroundColor $RealtimeColor
    Write-Host "    - Behavior Monitoring Active: $(!$Pref.DisableBehaviorMonitoring) (Required: True)" -ForegroundColor $BehaviorColor
    Write-Host "    - Exclusions Blocked: $($Pref.DisableLocalAdminConfiguration) (Required: True)" -ForegroundColor $ExclColor
    Write-Host "    - MAPS Reporting (Advanced): $($Pref.MAPSReporting) (Required: 2)" -ForegroundColor $MapsColor
    Write-Host "    - Submit Samples (Safe): $($Pref.SubmitSamplesConsent) (Required: 1)" -ForegroundColor $SamplesColor
    Write-Host "    - Cloud Protection Level: $($Pref.MpCloudBlockLevel) (Required: 2)" -ForegroundColor $CloudColor
    Write-Host "    - Script Scanning: $(!$Pref.DisableScriptScanning) (Required: True)" -ForegroundColor $ScriptColor
    Write-Host "    - Removable Drive Scanning: $(!$Pref.DisableRemovableDriveScanning) (Required: True)" -ForegroundColor $RemovableColor
    Write-Host "    - Network Protection: $($Pref.EnableNetworkProtection) (Required: 1)" -ForegroundColor $NetProtColor
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
$ServerRules = @(
    "56a863a9-875e-4185-98a7-b882c64b5ce5" # Vulnerable drivers
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" # LSASS
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" # Obfuscated scripts
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" # WMI persistence
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" # PSExec/WMI
    "c1db55ab-c21a-4637-bb3f-a12568109d35" # Ransomware
)

$EnforcedCount = 0
$AuditCount = 0

if (Test-Path $AsrRulesPath) {
    $Rules = Get-Item -Path $AsrRulesPath
    foreach ($RuleId in $ServerRules) {
        $ValData = $Rules.GetValue($RuleId)
        if ($ValData -eq "1" -or $ValData -eq 1) {
            $EnforcedCount++
        } elseif ($ValData -eq "2" -or $ValData -eq 2) {
            $AuditCount++
        }
    }
}

$AsrColor = if ($EnforcedCount -eq 5 -and $AuditCount -eq 1) { "Green" } else { "Yellow" }
Write-Host "    - Attack Surface Reduction: $EnforcedCount Block rules / $AuditCount Audit rules enforced (Required: 5 Block / 1 Audit)" -ForegroundColor $AsrColor
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9.47 (Exclusions restrictions), Section 18.9.30 (ASR Rules), Section 18.9.47.11 (Real-time protection)
* **ANSSI Active Directory Hardening Guide**: Recommendations regarding protective controls on Domain Controllers
