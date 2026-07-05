# [REQ-END-081] ASR: Block Adobe Reader from creating child processes

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
      * `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` = `1` (REG_SZ)

---

## Rationale
Prevents Adobe Reader from launching any child processes. Malicious PDF documents frequently attempt to exploit application vulnerabilities or trick users into executing embedded links, which spawns command shells (cmd.exe, powershell.exe) or scripting hosts (wscript.exe) to download and launch secondary malware payloads.

---

## Legacy Impact & Compatibility
Adobe Reader will be unable to launch external helper applications directly. PDF forms that rely on spawning external applications or customized plugins that execute command-line helpers will fail to run.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrAdobeChild.ps1](../../implementation_scripts/Configure-AsrAdobeChild.ps1)

```powershell
# Configure-AsrAdobeChild.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrAdobeChildStatus.ps1](../../audit_scripts/Get-AsrAdobeChildStatus.ps1)

```powershell
# Get-AsrAdobeChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -ErrorAction SilentlyContinue
if ($Value -and ($Value."7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -eq "1" -or $Value."7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" -eq 1)) {
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
