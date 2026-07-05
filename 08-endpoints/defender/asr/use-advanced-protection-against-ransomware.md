# [REQ-END-095] ASR: Use advanced protection against ransomware

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
      * `c1db55ab-c21a-4637-bb3f-a12568109d35` = `1` (REG_SZ)

---

## Rationale
Enables advanced behavioral heuristics and cloud analytics checks on files that attempt to modify multiple user files, detect signature-less encryption behavior, and block rapid write activity to prevent ransomware from encrypting system and user documents.

---

## Legacy Impact & Compatibility
Minor performance overhead when scanning active files during large batch edits or heavy database updates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `c1db55ab-c21a-4637-bb3f-a12568109d35` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrRansomware.ps1](../../implementation_scripts/Configure-AsrRansomware.ps1)

```powershell
# Configure-AsrRansomware.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "c1db55ab-c21a-4637-bb3f-a12568109d35" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrRansomwareStatus.ps1](../../audit_scripts/Get-AsrRansomwareStatus.ps1)

```powershell
# Get-AsrRansomwareStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "c1db55ab-c21a-4637-bb3f-a12568109d35" -ErrorAction SilentlyContinue
if ($Value -and ($Value."c1db55ab-c21a-4637-bb3f-a12568109d35" -eq "1" -or $Value."c1db55ab-c21a-4637-bb3f-a12568109d35" -eq 1)) {
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
