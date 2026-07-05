# [REQ-END-079] Enforce Antivirus Scan on Opening Attachments

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `User Configuration\Administrative Templates\Windows Components\Attachment Manager`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments`
      * `ScanWithAntiVirus` = `3` (REG_DWORD)

---

## Rationale
Forcing the Attachment Manager to notify the registered antivirus product when a user opens files downloaded from the web or email clients prevents initial access vectors.

---

## Legacy Impact & Compatibility
Opening unrecognized email attachments may have a slight latency while the file is analyzed.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: User Configuration\Administrative Templates\Windows Components\Attachment Manager
2. Set 'Notify antivirus programs when opening attachments' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DefenderAttachmentScan.ps1](../implementation_scripts/Configure-DefenderAttachmentScan.ps1)

```powershell
# Configure-DefenderAttachmentScan.ps1
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "ScanWithAntiVirus" -Value 3 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-DefenderAttachmentScanStatus.ps1](../audit_scripts/Get-DefenderAttachmentScanStatus.ps1)

```powershell
# Get-DefenderAttachmentScanStatus.ps1
$Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"
$Reg = Get-ItemProperty -Path $Path -Name "ScanWithAntiVirus" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.ScanWithAntiVirus -eq 3) {
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
