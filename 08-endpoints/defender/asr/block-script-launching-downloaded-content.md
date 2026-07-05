# [REQ-END-087] ASR: Block JavaScript or VBScript from launching downloaded executable content

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
      * `d3e037e1-3eb8-44c8-a917-57927947596d` = `1` (REG_SZ)

---

## Rationale
Prevents JavaScript or VBScript running locally from launching executable binaries that were downloaded from the internet. Attackers use malicious scripts inside documents or web browsers to download payloads (like ransomware or trojans) to the disk and launch them using local script engines.

---

## Legacy Impact & Compatibility
Local administrative script engines that perform software deployment or download updates and then launch installers will be blocked. These scripts must be replaced by structured configuration agents or signed installers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `d3e037e1-3eb8-44c8-a917-57927947596d` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrScriptLaunchExe.ps1](../../implementation_scripts/Configure-AsrScriptLaunchExe.ps1)

```powershell
# Configure-AsrScriptLaunchExe.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "d3e037e1-3eb8-44c8-a917-57927947596d" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrScriptLaunchExeStatus.ps1](../../audit_scripts/Get-AsrScriptLaunchExeStatus.ps1)

```powershell
# Get-AsrScriptLaunchExeStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "d3e037e1-3eb8-44c8-a917-57927947596d" -ErrorAction SilentlyContinue
if ($Value -and ($Value."d3e037e1-3eb8-44c8-a917-57927947596d" -eq "1" -or $Value."d3e037e1-3eb8-44c8-a917-57927947596d" -eq 1)) {
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
