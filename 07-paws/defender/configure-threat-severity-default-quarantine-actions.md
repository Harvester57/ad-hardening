# [REQ-PAW-071] Configure Threat Severity Default Quarantine Actions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Threats`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats`
      * `Threats_ThreatSeverityDefaultAction` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction`
      * `1` = `2` (REG_DWORD)

---

## Rationale
By default, Defender may prompt users or take actions (like clean/ignore) that leave malware remnants on the filesystem. Configuring default quarantine actions for all severities (low, medium, high, severe) ensures automated containment.

---

## Legacy Impact & Compatibility
None.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Threats
2. Set 'Specify threat alert levels at which default action should not be taken when detected' to 'Enabled'
3. Click 'Show...' and enter threat levels (1 -> 2, 2 -> 2, 4 -> 2, 5 -> 2)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderThreatActions.ps1](../implementation_scripts/Configure-PawDefenderThreatActions.ps1)

```powershell
# Configure-PawDefenderThreatActions.ps1
$ThreatsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats"
if (-not (Test-Path $ThreatsPath)) { New-Item -Path $ThreatsPath -Force | Out-Null }
Set-ItemProperty -Path $ThreatsPath -Name "Threats_ThreatSeverityDefaultAction" -Value 1 -Type DWord -Force
$ThreatsSevPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction"
if (-not (Test-Path $ThreatsSevPath)) { New-Item -Path $ThreatsSevPath -Force | Out-Null }
Set-ItemProperty -Path $ThreatsSevPath -Name "1" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "2" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "4" -Value 2 -Type DWord -Force
Set-ItemProperty -Path $ThreatsSevPath -Name "5" -Value 2 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderThreatActionsStatus.ps1](../audit_scripts/Get-PawDefenderThreatActionsStatus.ps1)

```powershell
# Get-PawDefenderThreatActionsStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats" -Name "Threats_ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
$RegSev = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.Threats_ThreatSeverityDefaultAction -eq 1) -and 
    ($RegSev -and $RegSev.1 -eq 2 -and $RegSev.2 -eq 2 -and $RegSev.4 -eq 2 -and $RegSev.5 -eq 2)) {
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
