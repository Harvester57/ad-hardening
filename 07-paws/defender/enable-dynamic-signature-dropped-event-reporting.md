# [REQ-PAW-066] Enable Dynamic Signature Dropped Event Reporting for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting`
      * `EnableDynamicSignatureDroppedEventReporting` = `1` (REG_DWORD)

---

## Rationale
Enabling this log report generation triggers explicit events when a dynamic scan ruleset signature is dropped. This ensures SIEM integrations can immediately log changes in the local threat signatures dataset.

---

## Legacy Impact & Compatibility
None.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting
2. Set 'Configure whether to report Dynamic Signature dropped events' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderDynamicReporting.ps1](../implementation_scripts/Configure-PawDefenderDynamicReporting.ps1)

```powershell
# Configure-PawDefenderDynamicReporting.ps1
$RepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if (-not (Test-Path $RepPath)) { New-Item -Path $RepPath -Force | Out-Null }
Set-ItemProperty -Path $RepPath -Name "EnableDynamicSignatureDroppedEventReporting" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderDynamicReportingStatus.ps1](../audit_scripts/Get-PawDefenderDynamicReportingStatus.ps1)

```powershell
# Get-PawDefenderDynamicReportingStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" -Name "EnableDynamicSignatureDroppedEventReporting" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.EnableDynamicSignatureDroppedEventReporting -eq 1) {
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
