# [REQ-DC-083] Configure Network Inspection System (NIS) settings on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

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
[Download Script: Configure-DefenderNis.ps1](../implementation_scripts/Configure-DefenderNis.ps1)

```powershell
# Configure-DefenderNis.ps1
$NisPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\NIS"
if (-not (Test-Path $NisPath)) { New-Item -Path $NisPath -Force | Out-Null }
Set-ItemProperty -Path $NisPath -Name "EnableConvertWarnToBlock" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NisPath -Name "AllowSwitchToAsyncInspection" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderNisStatus.ps1](../audit_scripts/Get-DefenderNisStatus.ps1)

```powershell
# Get-DefenderNisStatus.ps1
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
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
