# [REQ-END-092] ASR: Block process creations originating from PSExec and WMI commands

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
      * `d1e49aac-8f56-4280-b9ba-993a6d77406c` = `1` (REG_SZ)

---

## Rationale
Blocks processes created via WMI commands or PSExec remote execution utilities. This directly stops lateral movement attacks where compromised accounts or threat actors attempt to start commands, backdoors, or credential dumpers remotely across domain-joined servers and workstations.

---

## Legacy Impact & Compatibility
Disrupts remote administration tools, monitoring agents, and network scanners that rely on WMI/PSExec. For Domain Controllers or critical servers, this rule is often set to **Audit** mode (`2`) rather than hard Block mode (`1`) to prevent administrative downtime.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `d1e49aac-8f56-4280-b9ba-993a6d77406c` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrPsexecWmi.ps1](../../implementation_scripts/Configure-AsrPsexecWmi.ps1)

```powershell
# Configure-AsrPsexecWmi.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrPsexecWmiStatus.ps1](../../audit_scripts/Get-AsrPsexecWmiStatus.ps1)

```powershell
# Get-AsrPsexecWmiStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq "1" -or $Value."d1e49aac-8f56-4280-b9ba-993a6d77406c" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (ASR rules config)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on client workstations
