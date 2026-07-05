# [REQ-PAW-086] ASR: Block Office communication application from creating child processes for PAWs

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
      * `26190899-1602-49e8-8b27-eb1d0a1ce869` = `1` (REG_SZ)

---

## Rationale
Blocks Microsoft Outlook or other Office communication applications (e.g., Teams, Skype) from creating child processes. This prevents malware payloads delivered through emails, chats, or calendar invites from spawning command-line utilities or scripting environments.

---

## Legacy Impact & Compatibility
Outlook integrations or custom add-ins that legitimately spawn helper utilities, such as starting external browsers or custom document handlers directly, may be blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `26190899-1602-49e8-8b27-eb1d0a1ce869` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrOutlookChild.ps1](../../implementation_scripts/Configure-PawAsrOutlookChild.ps1)

```powershell
# Configure-PawAsrOutlookChild.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "26190899-1602-49e8-8b27-eb1d0a1ce869" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrOutlookChildStatus.ps1](../../audit_scripts/Get-PawAsrOutlookChildStatus.ps1)

```powershell
# Get-PawAsrOutlookChildStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "26190899-1602-49e8-8b27-eb1d0a1ce869" -ErrorAction SilentlyContinue
if ($Value -and ($Value."26190899-1602-49e8-8b27-eb1d0a1ce869" -eq "1" -or $Value."26190899-1602-49e8-8b27-eb1d0a1ce869" -eq 1)) {
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
