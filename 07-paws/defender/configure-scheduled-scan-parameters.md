# [REQ-PAW-068] Configure Scheduled Scan Parameters for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `ScheduleDay` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `DisableEmailScanning` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `DisableHeuristics` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan`
      * `DaysWithoutCatchupQuickScan` = `7` (REG_DWORD)

---

## Rationale
Ensuring daily scheduled scans, enabling heuristics for behavioral anomaly detection, scan mail attachments, and forcing a catchup scan after at most 7 days ensures system integrity is continually validated.

---

## Legacy Impact & Compatibility
Slight scanning overhead.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Scan
2. Set 'Specify the day of the week to run a scheduled scan' to 'Enabled' (Select 'Every day' or '0')
3. Set 'Turn on e-mail scanning' to 'Enabled'
4. Set 'Turn on heuristics' to 'Enabled'
5. Set 'Trigger a quick scan after X days without any scans' to 'Enabled' (7 days)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderScheduledScan.ps1](../implementation_scripts/Configure-PawDefenderScheduledScan.ps1)

```powershell
# Configure-PawDefenderScheduledScan.ps1
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableHeuristics $false
$ScanPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
if (-not (Test-Path $ScanPath)) { New-Item -Path $ScanPath -Force | Out-Null }
Set-ItemProperty -Path $ScanPath -Name "ScheduleDay" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableEmailScanning" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DisableHeuristics" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $ScanPath -Name "DaysWithoutCatchupQuickScan" -Value 7 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderScheduledScanStatus.ps1](../audit_scripts/Get-PawDefenderScheduledScanStatus.ps1)

```powershell
# Get-PawDefenderScheduledScanStatus.ps1
$Pref = Get-MpPreference
$RegDays = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DaysWithoutCatchupQuickScan" -ErrorAction SilentlyContinue
if ($Pref.DisableEmailScanning -eq $false -and $Pref.DisableHeuristics -eq $false -and ($RegDays -and $RegDays.DaysWithoutCatchupQuickScan -eq 7)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
