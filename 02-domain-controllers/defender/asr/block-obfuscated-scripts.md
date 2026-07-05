# [REQ-DC-100] ASR: Block execution of potentially obfuscated scripts on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules`
      * `5beb7efe-fd9a-4556-801d-275e5ffc04cc` = `1` (REG_SZ)

---

## Rationale
Blocks execution of obfuscated or encrypted scripts (such as PowerShell, VBScript, or JavaScript). Threat actors obfuscate their scripts using base64 encoding, custom string manipulation, or encryption to hide the intent of their code and bypass static file scanning and network detection engines.

---

## Legacy Impact & Compatibility
Legitimate administrative tools or third-party provisioning scripts that use heavy minification, obfuscation, or custom encoding wrappers will be blocked. Scripts must be refactored to use readable, signed code.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `5beb7efe-fd9a-4556-801d-275e5ffc04cc` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAsrObfuscatedScripts.ps1](../../implementation_scripts/Configure-DcAsrObfuscatedScripts.ps1)

```powershell
# Configure-DcAsrObfuscatedScripts.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-DcAsrObfuscatedScriptsStatus.ps1](../../audit_scripts/Get-DcAsrObfuscatedScriptsStatus.ps1)

```powershell
# Get-DcAsrObfuscatedScriptsStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "5beb7efe-fd9a-4556-801d-275e5ffc04cc" -ErrorAction SilentlyContinue
if ($Value -and ($Value."5beb7efe-fd9a-4556-801d-275e5ffc04cc" -eq "1" -or $Value."5beb7efe-fd9a-4556-801d-275e5ffc04cc" -eq 1)) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server Benchmark**: Section 18.9 (ASR rules config)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
