# [REQ-END-089] ASR: Block Office applications from injecting code into other processes

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
      * `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` = `1` (REG_SZ)

---

## Rationale
Blocks Microsoft Office applications from writing code or injecting threads directly into external processes. Threat actors use code injection (such as process hollowing or remote thread creation) inside Office macros to hide execution under clean, trusted system binaries like explorer.exe or svchost.exe.

---

## Legacy Impact & Compatibility
Office plugins or custom integration tools that inject threads or communicate with database engines using active injection libraries will be blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrOfficeInjection.ps1](../../implementation_scripts/Configure-AsrOfficeInjection.ps1)

```powershell
# Configure-AsrOfficeInjection.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrOfficeInjectionStatus.ps1](../../audit_scripts/Get-AsrOfficeInjectionStatus.ps1)

```powershell
# Get-AsrOfficeInjectionStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -ErrorAction SilentlyContinue
if ($Value -and ($Value."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -eq "1" -or $Value."75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" -eq 1)) {
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
