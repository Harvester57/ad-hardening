# [REQ-PAW-061] Enable EDR in Block Mode for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Features`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features`
      * `PassiveRemediation` = `1` (REG_DWORD)

---

## Rationale
Endpoint Detection and Response (EDR) in Block Mode allows Defender to take remediation actions on malicious artifacts detected by Microsoft Defender for Endpoint even if another non-Microsoft antivirus is primary. This establishes secondary defensive block capabilities.

---

## Legacy Impact & Compatibility
None. Extends passive monitoring to execute block operations when necessary.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Features
2. Set 'Enable EDR in block mode' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderEdrBlockMode.ps1](../implementation_scripts/Configure-PawDefenderEdrBlockMode.ps1)

```powershell
# Configure-PawDefenderEdrBlockMode.ps1
$FeaturesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features"
if (-not (Test-Path $FeaturesPath)) { New-Item -Path $FeaturesPath -Force | Out-Null }
Set-ItemProperty -Path $FeaturesPath -Name "PassiveRemediation" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderEdrBlockModeStatus.ps1](../audit_scripts/Get-PawDefenderEdrBlockModeStatus.ps1)

```powershell
# Get-PawDefenderEdrBlockModeStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Features" -Name "PassiveRemediation" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.PassiveRemediation -eq 1) {
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
