# [REQ-END-085] ASR: Block executable files from running unless they meet a prevalence, age, or trusted list criterion

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
      * `01443614-cd74-433a-b99e-2ecdc07bfc25` = `1` (REG_SZ)

---

## Rationale
Blocks execution of unrecognized, newly compiled, or low-prevalence executable files. This provides initial protection against zero-day malware campaigns and targeted custom payloads that have not yet established reputation telemetry in the Microsoft Cloud Protection network.

---

## Legacy Impact & Compatibility
Developers building and testing custom internal binaries, or administrators installing niche, uncertified third-party software updates will face false positives. Exclusions must be configured for target test directories.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `01443614-cd74-433a-b99e-2ecdc07bfc25` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrLowPrevalence.ps1](../../implementation_scripts/Configure-AsrLowPrevalence.ps1)

```powershell
# Configure-AsrLowPrevalence.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "01443614-cd74-433a-b99e-2ecdc07bfc25" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrLowPrevalenceStatus.ps1](../../audit_scripts/Get-AsrLowPrevalenceStatus.ps1)

```powershell
# Get-AsrLowPrevalenceStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "01443614-cd74-433a-b99e-2ecdc07bfc25" -ErrorAction SilentlyContinue
if ($Value -and ($Value."01443614-cd74-433a-b99e-2ecdc07bfc25" -eq "1" -or $Value."01443614-cd74-433a-b99e-2ecdc07bfc25" -eq 1)) {
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
