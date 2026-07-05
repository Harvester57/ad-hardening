# [REQ-DC-079] Prevent MAPS Local Setting Override on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
      * `SpynetReporting` = `0` (REG_DWORD)

---

## Rationale
Preventing local overrides of Microsoft Active Protection Service (MAPS) reporting ensures that Domain Controllers consistently report telemetry and signature feedback to cloud resources, preserving centralized protective visibility.

---

## Legacy Impact & Compatibility
Local system administrators cannot opt-out of telemetry reporting.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS
2. Set 'Join Microsoft MAPS' to 'Disabled' (or prevent override to SpynetReporting = 0)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderSpynetDC.ps1](../implementation_scripts/Configure-DefenderSpynetDC.ps1)

```powershell
# Configure-DefenderSpynetDC.ps1
$SpynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (-not (Test-Path $SpynetPath)) { New-Item -Path $SpynetPath -Force | Out-Null }
Set-ItemProperty -Path $SpynetPath -Name "SpynetReporting" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderSpynetDCStatus.ps1](../audit_scripts/Get-DefenderSpynetDCStatus.ps1)

```powershell
# Get-DefenderSpynetDCStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.SpynetReporting -eq 0) {
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
