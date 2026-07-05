# [REQ-DC-084] Configure OOBE Real-Time Protection and Security Intelligence on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`
      * `OobeEnableRtpAndSigUpdate` = `1` (REG_DWORD)

---

## Rationale
Enabling real-time protection and intelligence updates during the Out-of-Box Experience (OOBE) ensures that the system is fully updated and protected before the initial administrative user signs in or connects to enterprise network nodes.

---

## Legacy Impact & Compatibility
Negligible. Minor network traffic during initial provisioning phases.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Real-time Protection
2. Set 'Configure real-time protection and Security Intelligence Updates during OOBE' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderOobeRtp.ps1](../implementation_scripts/Configure-DefenderOobeRtp.ps1)

```powershell
# Configure-DefenderOobeRtp.ps1
$RtpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
if (-not (Test-Path $RtpPath)) { New-Item -Path $RtpPath -Force | Out-Null }
Set-ItemProperty -Path $RtpPath -Name "OobeEnableRtpAndSigUpdate" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderOobeRtpStatus.ps1](../audit_scripts/Get-DefenderOobeRtpStatus.ps1)

```powershell
# Get-DefenderOobeRtpStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "OobeEnableRtpAndSigUpdate" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.OobeEnableRtpAndSigUpdate -eq 1) {
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
