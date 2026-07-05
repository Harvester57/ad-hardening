# [REQ-PAW-087] ASR: Block persistence through WMI event subscription for PAWs

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
      * `e6db77e5-3df2-4cf1-b95a-636979351e5b` = `1` (REG_SZ)

---

## Rationale
Blocks threat actors from achieving system persistence by registering permanent Windows Management Instrumentation (WMI) event subscriptions. WMI event subscriptions allow attackers to automatically launch malicious payloads when system triggers occur (like system boot or user logon) without using traditional startup registry keys.

---

## Legacy Impact & Compatibility
Management software or diagnostic monitoring tools that legitimately register permanent WMI event filters to track system telemetry will be blocked. Alternatives like Windows services or scheduled tasks must be used.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `e6db77e5-3df2-4cf1-b95a-636979351e5b` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrWmiPersistence.ps1](../../implementation_scripts/Configure-PawAsrWmiPersistence.ps1)

```powershell
# Configure-PawAsrWmiPersistence.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "e6db77e5-3df2-4cf1-b95a-636979351e5b" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrWmiPersistenceStatus.ps1](../../audit_scripts/Get-PawAsrWmiPersistenceStatus.ps1)

```powershell
# Get-PawAsrWmiPersistenceStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "e6db77e5-3df2-4cf1-b95a-636979351e5b" -ErrorAction SilentlyContinue
if ($Value -and ($Value."e6db77e5-3df2-4cf1-b95a-636979351e5b" -eq "1" -or $Value."e6db77e5-3df2-4cf1-b95a-636979351e5b" -eq 1)) {
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
