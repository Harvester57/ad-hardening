# [REQ-PAW-060] Configure Auto Exclusions Configuration for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Exclusions`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`
      * `DisableAutoExclusions` = `0` (REG_DWORD)

---

## Rationale
Auto Exclusions automatically configure exclusions for known safe system folders or server roles to reduce performance overhead. Enforcing that auto exclusions are not disabled ensures server performance stability and proper system scanning.

---

## Legacy Impact & Compatibility
None.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Exclusions
2. Set 'Turn off Auto Exclusions' to 'Disabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderAutoExclusions.ps1](../implementation_scripts/Configure-PawDefenderAutoExclusions.ps1)

```powershell
# Configure-PawDefenderAutoExclusions.ps1
$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) { New-Item -Path $ExclPath -Force | Out-Null }
Set-ItemProperty -Path $ExclPath -Name "DisableAutoExclusions" -Value 0 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderAutoExclusionsStatus.ps1](../audit_scripts/Get-PawDefenderAutoExclusionsStatus.ps1)

```powershell
# Get-PawDefenderAutoExclusionsStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Name "DisableAutoExclusions" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.DisableAutoExclusions -eq 0) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 18.9 (Windows Defender Antivirus configuration parameters)
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
