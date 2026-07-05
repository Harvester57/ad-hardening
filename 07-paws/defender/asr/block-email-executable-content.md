# [REQ-PAW-080] ASR: Block executable content from email client and webmail for PAWs

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
      * `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` = `1` (REG_SZ)

---

## Rationale
Prevents executable files (such as .exe, .com, .scr, .vbs, .js, or .pif) from launching directly from email clients (like Outlook) or webmail accessed via browser sessions. This stops phishing attacks where users accidentally launch malicious attachments or download payloads directly from web-based email links.

---

## Legacy Impact & Compatibility
Users will be blocked from directly launching attachments that contain scripts, setup files, or macros. They must first save the file to an authorized directory and run it from there (which allows standard real-time scans to run first).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrEmailExecutable.ps1](../../implementation_scripts/Configure-PawAsrEmailExecutable.ps1)

```powershell
# Configure-PawAsrEmailExecutable.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrEmailExecutableStatus.ps1](../../audit_scripts/Get-PawAsrEmailExecutableStatus.ps1)

```powershell
# Get-PawAsrEmailExecutableStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -ErrorAction SilentlyContinue
if ($Value -and ($Value."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -eq "1" -or $Value."be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" -eq 1)) {
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
