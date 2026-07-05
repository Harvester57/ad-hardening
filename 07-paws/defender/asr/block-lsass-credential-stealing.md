# [REQ-PAW-079] ASR: Block credential stealing from the Windows local security authority subsystem for PAWs

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
      * `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` = `1` (REG_SZ)

---

## Rationale
Blocks attempts to open or dump the memory of the Local Security Authority Subsystem Service (lsass.exe). Attackers dump LSASS memory using tools like Mimikatz or Task Manager to extract plaintext credentials, Kerberos tickets, or NTLM password hashes from system memory for lateral movement.

---

## Legacy Impact & Compatibility
Administrative diagnostic tools, customized authentication packages, or security scanners that attempt to open the LSASS process handle to read user tokens or perform access auditing will be blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrLsassDump.ps1](../../implementation_scripts/Configure-PawAsrLsassDump.ps1)

```powershell
# Configure-PawAsrLsassDump.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrLsassDumpStatus.ps1](../../audit_scripts/Get-PawAsrLsassDumpStatus.ps1)

```powershell
# Get-PawAsrLsassDumpStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -ErrorAction SilentlyContinue
if ($Value -and ($Value."9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -eq "1" -or $Value."9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -eq 1)) {
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
