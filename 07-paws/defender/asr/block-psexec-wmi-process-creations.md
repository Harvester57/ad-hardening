# [REQ-PAW-088] ASR: Block process creations originating from PSExec and WMI commands for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Blocks processes created via WMI commands or PSExec remote execution utilities. This directly stops lateral movement attacks where compromised accounts or threat actors attempt to start commands, backdoors, or credential dumpers remotely across domain-joined servers and PAW platforms.

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
[Download Script: Configure-PawAsrPsexecWmi.ps1](../../implementation_scripts/Configure-PawAsrPsexecWmi.ps1)

```powershell
# Configure-PawAsrPsexecWmi.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "d1e49aac-8f56-4280-b9ba-993a6d77406c" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrPsexecWmiStatus.ps1](../../audit_scripts/Get-PawAsrPsexecWmiStatus.ps1)

```powershell
# Get-PawAsrPsexecWmiStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
