# [REQ-DC-095] Disable Generic Reports on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `DisableGenericRePorts` = `1` (REG_DWORD)

---

## Rationale
Disabling generic telemetry and reports on Domain Controllers restricts the transmission of potentially sensitive metadata or environment data regarding Tier 0 directory services to external cloud resources.

---

## Legacy Impact & Compatibility
Limits some automated telemetry diagnostics sent to Microsoft support logs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Reporting
2. Set 'Configure generic reports' to 'Disabled' (or set DisableGenericRePorts = 1)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderDisableGenericReports.ps1](../implementation_scripts/Configure-DefenderDisableGenericReports.ps1)

```powershell
# Configure-DefenderDisableGenericReports.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableGenericRePorts" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderDisableGenericReportsStatus.ps1](../audit_scripts/Get-DefenderDisableGenericReportsStatus.ps1)

```powershell
# Get-DefenderDisableGenericReportsStatus.ps1
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$Reg = Get-ItemProperty -Path $Path -Name "DisableGenericRePorts" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableGenericRePorts -eq 1) {
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
