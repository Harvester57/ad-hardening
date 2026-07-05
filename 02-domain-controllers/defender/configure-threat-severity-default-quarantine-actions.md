# [REQ-DC-090] Configure Threat Severity Default Quarantine Actions on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

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
[Download Script: Configure-DefenderThreatActions.ps1](../implementation_scripts/Configure-DefenderThreatActions.ps1)

```powershell
# Configure-DefenderThreatActions.ps1
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
[Download Script: Get-DefenderThreatActionsStatus.ps1](../audit_scripts/Get-DefenderThreatActionsStatus.ps1)

```powershell
# Get-DefenderThreatActionsStatus.ps1
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
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
