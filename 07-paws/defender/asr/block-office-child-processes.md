# [REQ-PAW-078] ASR: Block all Office applications from creating child processes for PAWs

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
      * `d4f940ab-401b-4efc-aadc-ad5f3c50688a` = `1` (REG_SZ)

---

## Rationale
Blocks Microsoft Office applications (Word, Excel, PowerPoint) from creating child processes. This prevents malicious files containing embedded VBA macros or exploiting unpatched vulnerabilities (such as CVE-2021-40444) from launching scripting environments or system commands to download and execute code.

---

## Legacy Impact & Compatibility
Office macros that legitimately launch external scripts, shell scripts, or third-party executable helpers will be blocked. Business processes relying on advanced inter-process macros must be rewritten to use modern API alternatives.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `d4f940ab-401b-4efc-aadc-ad5f3c50688a` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrOfficeChild.ps1](../../implementation_scripts/Configure-PawAsrOfficeChild.ps1)

```powershell
# Configure-PawAsrOfficeChild.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrOfficeChildStatus.ps1](../../audit_scripts/Get-PawAsrOfficeChildStatus.ps1)

```powershell
# Get-PawAsrOfficeChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d4f940ab-401b-4efc-aadc-ad5f3c50688a" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d4f940ab-401b-4efc-aadc-ad5f3c50688a" -eq "1" -or $Value."d4f940ab-401b-4efc-aadc-ad5f3c50688a" -eq 1)) {
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
