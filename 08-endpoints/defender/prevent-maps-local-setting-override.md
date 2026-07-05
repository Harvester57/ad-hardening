# [REQ-END-061] Prevent MAPS Local Setting Override

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet`
      * `LocalSettingOverrideSpynetReporting` = `0` (REG_DWORD)

---

## Rationale
Preventing local overrides of Microsoft Active Protection Service (MAPS) reporting ensures that endpoints consistently report telemetry and signature feedback to cloud resources, preserving centralized protective visibility.

---

## Legacy Impact & Compatibility
Local system administrators cannot opt-out of telemetry reporting.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MAPS
2. Set 'Configure local setting override for reporting to Microsoft MAPS' to 'Disabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderMapsOverride.ps1](../implementation_scripts/Configure-DefenderMapsOverride.ps1)

```powershell
# Configure-DefenderMapsOverride.ps1
$SpynetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
if (-not (Test-Path $SpynetPath)) { New-Item -Path $SpynetPath -Force | Out-Null }
Set-ItemProperty -Path $SpynetPath -Name "LocalSettingOverrideSpynetReporting" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderMapsOverrideStatus.ps1](../audit_scripts/Get-DefenderMapsOverrideStatus.ps1)

```powershell
# Get-DefenderMapsOverrideStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.LocalSettingOverrideSpynetReporting -eq 0) {
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
