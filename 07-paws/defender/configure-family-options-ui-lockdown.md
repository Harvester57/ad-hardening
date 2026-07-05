# [REQ-PAW-072] Configure Family Options UI Lockdown for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Security\Family options`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options`
      * `UILockdown` = `1` (REG_DWORD)

---

## Rationale
Locking down non-essential components of the Windows Security Center interface prevents users from tampering with parental or diagnostic UI controls on enterprise assets.

---

## Legacy Impact & Compatibility
None.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Security\Family options
2. Set 'Hide the Family options area' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderFamilyLockdown.ps1](../implementation_scripts/Configure-PawDefenderFamilyLockdown.ps1)

```powershell
# Configure-PawDefenderFamilyLockdown.ps1
$FamilyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options"
if (-not (Test-Path $FamilyPath)) { New-Item -Path $FamilyPath -Force | Out-Null }
Set-ItemProperty -Path $FamilyPath -Name "UILockdown" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderFamilyLockdownStatus.ps1](../audit_scripts/Get-PawDefenderFamilyLockdownStatus.ps1)

```powershell
# Get-PawDefenderFamilyLockdownStatus.ps1
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options" -Name "UILockdown" -ErrorAction SilentlyContinue
if ($Reg -and $Reg.UILockdown -eq 1) {
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
