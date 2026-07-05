# [REQ-END-070] Configure Security Intelligence Update Schedule

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Security Intelligence Updates`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`
      * `ASSignatureDue` = `7` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`
      * `AVSignatureDue` = `7` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates`
      * `ScheduleDay` = `0` (REG_DWORD)

---

## Rationale
Antivirus signatures must remain fresh to block the latest published threats. Mandating daily checks for updates and marking signatures older than 7 days as out-of-date ensures continuous defense parity.

---

## Legacy Impact & Compatibility
Requires continuous outbound connectivity to WSUS or Microsoft Update endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Security Intelligence Updates
2. Set 'Define the number of days before spyware security intelligence is considered out of date' to 'Enabled' (7 days)
3. Set 'Define the number of days before virus security intelligence is considered out of date' to 'Enabled' (7 days)
4. Set 'Specify the day of the week to check for security intelligence updates' to 'Enabled' (Every day or 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderUpdateSchedule.ps1](../implementation_scripts/Configure-DefenderUpdateSchedule.ps1)

```powershell
# Configure-DefenderUpdateSchedule.ps1
$SigPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates"
if (-not (Test-Path $SigPath)) { New-Item -Path $SigPath -Force | Out-Null }
Set-ItemProperty -Path $SigPath -Name "ASSignatureDue" -Value 7 -Type DWord -Force
Set-ItemProperty -Path $SigPath -Name "AVSignatureDue" -Value 7 -Type DWord -Force
Set-ItemProperty -Path $SigPath -Name "ScheduleDay" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderUpdateScheduleStatus.ps1](../audit_scripts/Get-DefenderUpdateScheduleStatus.ps1)

```powershell
# Get-DefenderUpdateScheduleStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ASSignatureDue" -ErrorAction SilentlyContinue
$RegAV = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "AVSignatureDue" -ErrorAction SilentlyContinue
$RegDay = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Name "ScheduleDay" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.ASSignatureDue -eq 7) -and ($RegAV -and $RegAV.AVSignatureDue -eq 7) -and ($RegDay -and $RegDay.ScheduleDay -eq 0)) {
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
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
