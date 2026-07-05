# [REQ-DC-102] ASR: Block process creations originating from PSExec and WMI commands on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
      * `d1e49aac-8f56-4280-b9ba-993a6d77406c` = `2` (REG_SZ)

---

## Rationale
Blocks processes created via WMI commands or PSExec remote execution utilities. This directly stops lateral movement attacks where compromised accounts or threat actors attempt to start commands, backdoors, or credential dumpers remotely across domain-joined servers and Domain Controllers.

---

## Legacy Impact & Compatibility
Configured in Audit mode (2) to monitor remote execution commands, ensuring administrative agents and orchestration tools are logged without operational block impact.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `d1e49aac-8f56-4280-b9ba-993a6d77406c` as Value Name, with Value set to `2` (Audit).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAsrPsexecWmi.ps1](../../implementation_scripts/Configure-DcAsrPsexecWmi.ps1)

```powershell
# Configure-DcAsrPsexecWmi.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -Value "2" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-DcAsrPsexecWmiStatus.ps1](../../audit_scripts/Get-DcAsrPsexecWmiStatus.ps1)

```powershell
# Get-DcAsrPsexecWmiStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq "2" -or $Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq 2)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (ASR rules config)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
