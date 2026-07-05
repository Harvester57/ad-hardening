# [REQ-DC-082] Enable File Hash Computation on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MpEngine`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine`
      * `EnableFileHashComputation` = `1` (REG_DWORD)

---

## Rationale
Computing cryptographic file hashes allows Defender to pass hashes of scanned files to cloud and SIEM Domain Controllers. This enables precise IOC matches, file tracking, and correlation with threat intelligence repositories.

---

## Legacy Impact & Compatibility
Minor CPU/Disk I/O impact when scanning large directories.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\MpEngine
2. Set 'Enable file hash computation feature' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderFileHash.ps1](../implementation_scripts/Configure-DefenderFileHash.ps1)

```powershell
# Configure-DefenderFileHash.ps1
Set-MpPreference -EnableFileHashComputation $true
$MpEnginePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine"
if (-not (Test-Path $MpEnginePath)) { New-Item -Path $MpEnginePath -Force | Out-Null }
Set-ItemProperty -Path $MpEnginePath -Name "EnableFileHashComputation" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderFileHashStatus.ps1](../audit_scripts/Get-DefenderFileHashStatus.ps1)

```powershell
# Get-DefenderFileHashStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" -Name "EnableFileHashComputation" -ErrorAction SilentlyContinue
if ($Pref.EnableFileHashComputation -eq $true -or ($Reg -and $Reg.EnableFileHashComputation -eq 1)) {
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
