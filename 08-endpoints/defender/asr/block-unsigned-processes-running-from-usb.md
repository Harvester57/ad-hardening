# [REQ-END-093] ASR: Block untrusted and unsigned processes that run from USB

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
      * `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` = `1` (REG_SZ)

---

## Rationale
Blocks the execution of unsigned or untrusted processes on removable storage devices (USB drives, external SSDs). This stops physical access vectors, rogue USB drops, and automated worm propagation techniques from running unauthorized installers or scripts.

---

## Legacy Impact & Compatibility
Administrators or developers will be unable to run unsigned utilities directly from portable flash drives. Software must be copied to local trusted storage, or the binary must possess a trusted digital signature.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AsrUsbUnsigned.ps1](../../implementation_scripts/Configure-AsrUsbUnsigned.ps1)

```powershell
# Configure-AsrUsbUnsigned.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-AsrUsbUnsignedStatus.ps1](../../audit_scripts/Get-AsrUsbUnsignedStatus.ps1)

```powershell
# Get-AsrUsbUnsignedStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -ErrorAction SilentlyContinue
if ($Value -and ($Value."b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -eq "1" -or $Value."b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" -eq 1)) {
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
