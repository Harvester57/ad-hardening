# [REQ-PAW-064] Configure Network Inspection System (NIS) settings for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Network Inspection System`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS`
      * `EnableConvertWarnToBlock` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS`
      * `AllowSwitchToAsyncInspection` = `1` (REG_DWORD)

---

## Rationale
The Network Inspection System (NIS) inspects network traffic patterns for known exploits. Converting warning verdicts to block enforces inline blocking of zero-day exploits, while allowing async inspection prevents performance overhead from slowing local network interfaces.

---

## Legacy Impact & Compatibility
None.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Network Inspection System
2. Set 'Convert warn verdict to block' to 'Enabled'
3. Set 'Turn on asynchronous inspection' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderNis.ps1](../implementation_scripts/Configure-PawDefenderNis.ps1)

```powershell
# Configure-PawDefenderNis.ps1
$NisPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS"
if (-not (Test-Path $NisPath)) { New-Item -Path $NisPath -Force | Out-Null }
Set-ItemProperty -Path $NisPath -Name "EnableConvertWarnToBlock" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NisPath -Name "AllowSwitchToAsyncInspection" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderNisStatus.ps1](../audit_scripts/Get-PawDefenderNisStatus.ps1)

```powershell
# Get-PawDefenderNisStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS" -Name "EnableConvertWarnToBlock" -ErrorAction SilentlyContinue
$RegAsync = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS" -Name "AllowSwitchToAsyncInspection" -ErrorAction SilentlyContinue
if (($Reg -and $Reg.EnableConvertWarnToBlock -eq 1) -and ($RegAsync -and $RegAsync.AllowSwitchToAsyncInspection -eq 1)) {
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
