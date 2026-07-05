# [REQ-DC-076] Configure Potentially Unwanted Applications (PUA) Protection on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `PUAProtection` = `1` (REG_DWORD)

---

## Rationale
Potentially Unwanted Applications (PUA) include adware, torrent clients, cryptominers, and system optimizers that increase risk and resource consumption. Forcing PUA blocking stops standard vectors of shadow IT and unauthorized utility tool execution.

---

## Legacy Impact & Compatibility
Legitimate but unrecognized administrative utilities may be blocked. Standard exclusions must be configured for approved utilities.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus
2. Set 'Configure detection for potentially unwanted applications' to 'Enabled'
3. Select 'Block' in the options dropdown list

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderPUA.ps1](../implementation_scripts/Configure-DefenderPUA.ps1)

```powershell
# Configure-DefenderPUA.ps1
Set-MpPreference -PUAProtection 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderPUAStatus.ps1](../audit_scripts/Get-DefenderPUAStatus.ps1)

```powershell
# Get-DefenderPUAStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue
if ($Pref.PUAProtection -eq 1 -or ($Reg -and $Reg.PUAProtection -eq 1)) {
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
