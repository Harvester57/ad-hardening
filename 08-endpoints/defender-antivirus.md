# Hardening Requirement: Windows Defender Antivirus Offline Baseline

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus
  * HKLM\SOFTWARE\Policies\Microsoft\Windows Defender

---

## Rationale
Windows Defender Antivirus is the built-in anti-malware engine on Windows endpoints. In an air-gapped network, Windows Defender cannot query Microsoft cloud services for file reputations in real-time, making local protection capabilities even more critical.

Hardening Windows Defender for offline operation ensures:
1. **Real-Time Scanning**: Files, downloads, and attachments are scanned in real-time when accessed.
2. **Behavioral Monitoring**: Identifies suspicious program behaviors to block zero-day or runtime exploits, even when offline signature updates are slightly delayed.
3. **Exclusion Lockdown**: Prevents local users or compromised accounts from adding directory or file exclusions (which attackers use to bypass anti-virus scanning in their payload staging folders).
4. **Offline Update Schedules**: Ensures the client continuously checks for and imports definition updates imported via WSUS or offline scripts.

---

## Legacy Impact & Compatibility
* **Offline Signature Updates**: Administrators must ensure that virus definition updates (`mpam-fe.exe` or signature files) are synchronized to the internal WSUS server or deployed via automated scripts.
* **Performance Impact**: Real-time scanning can introduce minor CPU/Disk latency during compilation tasks, high-volume file transfers, or executing database engines. Exclusions for trusted database files (e.g., local SQL databases) must be managed centrally via GPO.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
4. Configure the following settings:
   * **Policy**: `Turn off Windows Defender Antivirus`
   * **Setting**: `Disabled` (ensures it is active)
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

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enforce Windows Defender Antivirus parameters via registry commands and cmdlet preferences.

```powershell
# Set-DefenderOfflineBaseline.ps1
# Configures Windows Defender Antivirus local options for real-time monitoring and exclusion restriction.

Write-Host "--- Applying Windows Defender Baseline ---" -ForegroundColor Cyan

# 1. Enable Defender Real-time Protection and Behavioral Monitoring via PowerShell Cmdlets
if (Get-Command Set-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "[+] Configuring Defender parameters via Set-MpPreference..." -ForegroundColor Gray
    
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false # Downloaded files scan
    Set-MpPreference -DisableBlockAtFirstSeen $true # Disable cloud dependency for block-at-first-seen in air-gap
    Set-MpPreference -DisableExclusionRestriction $false # Enforce restriction
    
    Write-Host "    Windows Defender baseline preferences applied." -ForegroundColor Green
} else {
    Write-Warning "Set-MpPreference cmdlet is not available on this operating system version."
}

# 2. Enforce Exclusion restrictions in Registry
$DefenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $DefenderPath)) {
    New-Item -Path $DefenderPath -Force | Out-Null
}
# DisableAntiSpyware = 0 ensures Defender is enabled
Set-ItemProperty -Path $DefenderPath -Name "DisableAntiSpyware" -Value 0 -Type DWord

$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) {
    New-Item -Path $ExclPath -Force | Out-Null
}
Set-ItemProperty -Path $ExclPath -Name "DisableLocalAdminConfiguration" -Value 1 -Type DWord
Write-Host "[+] Exclusion restriction configured in registry." -ForegroundColor Green
```

*To audit the local Windows Defender status:*
```powershell
# Test-DefenderOfflineStatus.ps1
# Audits the local Defender configuration for baseline settings.

Write-Host "--- Auditing Windows Defender Status ---" -ForegroundColor Cyan

if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    $Pref = Get-MpPreference
    
    $RealtimeColor = if ($Pref.DisableRealtimeMonitoring -eq $false) { "Green" } else { "Red" }
    $BehaviorColor = if ($Pref.DisableBehaviorMonitoring -eq $false) { "Green" } else { "Red" }
    $ExclColor = if ($Pref.DisableLocalAdminConfiguration -eq 1 -or $Pref.DisableLocalAdminConfiguration -eq $true) { "Green" } else { "Red" }
    
    Write-Host "    - Real-Time Monitoring Inactive: $($Pref.DisableRealtimeMonitoring) (Required = False)" -ForegroundColor $RealtimeColor
    Write-Host "    - Behavior Monitoring Inactive: $($Pref.DisableBehaviorMonitoring) (Required = False)" -ForegroundColor $BehaviorColor
    Write-Host "    - Exclusion Configuration Blocked: $($Pref.DisableLocalAdminConfiguration) (Required = True)" -ForegroundColor $ExclColor
} else {
    Write-Warning "Get-MpPreference cmdlet not available."
}
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9.47 (Exclusions restrictions), Section 18.9.47.11 (Turn on real-time protection)
* **Microsoft Security Baselines**: Windows Defender baseline standards for Enterprise Client security.
