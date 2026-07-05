# [REQ-END-067] Enable Dynamic Signature Dropped Event Reporting

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

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
[Download Script: Configure-DefenderDynamicReporting.ps1](../implementation_scripts/Configure-DefenderDynamicReporting.ps1)

```powershell
# Configure-DefenderDynamicReporting.ps1
$RepPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
if (-not (Test-Path $RepPath)) { New-Item -Path $RepPath -Force | Out-Null }
Set-ItemProperty -Path $RepPath -Name "EnableDynamicSignatureDroppedEventReporting" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderDynamicReportingStatus.ps1](../audit_scripts/Get-DefenderDynamicReportingStatus.ps1)

```powershell
# Get-DefenderDynamicReportingStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
