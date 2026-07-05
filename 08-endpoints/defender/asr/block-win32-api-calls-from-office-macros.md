# [REQ-END-094] ASR: Block Win32 API calls from Office macros

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
      * `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` = `1` (REG_SZ)

---

## Rationale
Blocks VBA macros inside Microsoft Office documents from invoking Win32 API calls. Malicious documents use macros to call kernel memory functions (such as VirtualAlloc, WriteProcessMemory, or CreateThread) to load and execute shellcode in memory without dropping files to disk, bypassing file scanners.

---

## Legacy Impact & Compatibility
Advanced business spreadsheets or database documents that utilize Win32 API calls for custom UI rendering, network calls, or system commands will fail. They must be rewritten using standard secure VBA structures or add-in APIs.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrOfficeWin32Calls.ps1](../../implementation_scripts/Configure-AsrOfficeWin32Calls.ps1)

```powershell
# Configure-AsrOfficeWin32Calls.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrOfficeWin32CallsStatus.ps1](../../audit_scripts/Get-AsrOfficeWin32CallsStatus.ps1)

```powershell
# Get-AsrOfficeWin32CallsStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -ErrorAction SilentlyContinue
if ($Value -and ($Value."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -eq "1" -or $Value."92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" -eq 1)) {
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
