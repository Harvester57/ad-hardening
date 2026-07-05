# [REQ-PAW-076] ASR: Block abuse of exploited vulnerable signed drivers for PAWs

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
      * `56a863a9-875e-4185-98a7-b882c64b5ce5` = `1` (REG_SZ)

---

## Rationale
Prevents an application from writing a vulnerable signed driver to disk. Attackers use Bring Your Own Vulnerable Driver (BYOVD) techniques to bypass Windows kernel protections by loading legitimate, signed third-party drivers that contain known vulnerabilities, allowing them to disable security agents and gain kernel-level privileges.

---

## Legacy Impact & Compatibility
Administrators or developers who deliberately load older or specific signed debugging/hardware diagnostics drivers containing known security bugs will be blocked. Approvals or exclusions must be configured for these specific drivers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Windows Defender Exploit Guard\Attack Surface Reduction
2. Set 'Configure Attack Surface Reduction rules' to 'Enabled'
3. Click 'Show...' and add the rule GUID `56a863a9-875e-4185-98a7-b882c64b5ce5` as Value Name, with Value set to `1` (Block).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAsrVulnerableDrivers.ps1](../../implementation_scripts/Configure-PawAsrVulnerableDrivers.ps1)

```powershell
# Configure-PawAsrVulnerableDrivers.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
if (-not (Test-Path $AsrRulesPath)) { New-Item -Path $AsrRulesPath -Force | Out-Null }
Set-ItemProperty -Path $AsrRulesPath -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" -Value "1" -Type String -Force
```

*To audit the hardening status:*
[Download Script: Get-PawAsrVulnerableDriversStatus.ps1](../../audit_scripts/Get-PawAsrVulnerableDriversStatus.ps1)

```powershell
# Get-PawAsrVulnerableDriversStatus.ps1
$AsrRulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$Value = Get-ItemProperty -Path $AsrRulesPath -Name "56a863a9-875e-4185-98a7-b882c64b5ce5" -ErrorAction SilentlyContinue
if ($Value -and ($Value."56a863a9-875e-4185-98a7-b882c64b5ce5" -eq "1" -or $Value."56a863a9-875e-4185-98a7-b882c64b5ce5" -eq 1)) {
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
