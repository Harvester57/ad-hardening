# [REQ-END-088] ASR: Block Office applications from creating executable content

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
      * `3b576869-a4ec-4529-8536-b80a7769e899` = `1` (REG_SZ)

---

## Rationale
Prevents Microsoft Office applications (Word, Excel, PowerPoint) from creating or writing executable files (e.g., .exe, .dll, .scr) to the local filesystem. Malicious documents often attempt to drop payloads directly into the local temp folders or AppData directories before executing them.

---

## Legacy Impact & Compatibility
Macros or add-ins that legitimately save external binaries or compile executable helper objects locally will be blocked.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `3b576869-a4ec-4529-8536-b80a7769e899` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrOfficeWriteExe.ps1](../../implementation_scripts/Configure-AsrOfficeWriteExe.ps1)

```powershell
# Configure-AsrOfficeWriteExe.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "3b576869-a4ec-4529-8536-b80a7769e899" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrOfficeWriteExeStatus.ps1](../../audit_scripts/Get-AsrOfficeWriteExeStatus.ps1)

```powershell
# Get-AsrOfficeWriteExeStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "3b576869-a4ec-4529-8536-b80a7769e899" -ErrorAction SilentlyContinue
if ($Value -and ($Value."3b576869-a4ec-4529-8536-b80a7769e899" -eq "1" -or $Value."3b576869-a4ec-4529-8536-b80a7769e899" -eq 1)) {
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
