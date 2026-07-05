# [REQ-PAW-059] Prevent Local List Merging and Exclusions Configuration for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus`
  * **Registry Location**:
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `DisableLocalAdminMerge` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
      * `HideExclusionsFromLocalAdmins` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions`
      * `DisableLocalAdminConfiguration` = `1` (REG_DWORD)

---

## Rationale
If local administrators or compromised administrative accounts can modify Defender exclusions or merge local lists, they can authorize malicious folders or tools. Restricting list configuration to central GPOs ensures consistent security enforcement.

---

## Legacy Impact & Compatibility
Local administrators will be unable to add folders or scripts to Defender exclusions. All exclusions must be managed centrally via GPO.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus
2. Set 'Configure local administrator merge behavior for lists' to 'Disabled'
3. Navigate to: Computer Configuration\Administrative Templates\Windows Components\Windows Defender Antivirus\Exclusions
4. Set 'Prevent users from configuring exclusions' to 'Enabled'
5. Set 'Control whether or not exclusions are visible to Local Admins' to 'Enabled'

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawDefenderLocalExclusions.ps1](../implementation_scripts/Configure-PawDefenderLocalExclusions.ps1)

```powershell
# Configure-PawDefenderLocalExclusions.ps1
Set-MpPreference -DisableLocalAdminMerge $true
Set-MpPreference -DisableExclusionRestriction $false
$Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
Set-ItemProperty -Path $Path -Name "DisableLocalAdminMerge" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $Path -Name "HideExclusionsFromLocalAdmins" -Value 1 -Type DWord -Force
$ExclPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
if (-not (Test-Path $ExclPath)) { New-Item -Path $ExclPath -Force | Out-Null }
Set-ItemProperty -Path $ExclPath -Name "DisableLocalAdminConfiguration" -Value 1 -Type DWord -Force
```

*To audit the hardening status:*
[Download Script: Get-PawDefenderLocalExclusionsStatus.ps1](../audit_scripts/Get-PawDefenderLocalExclusionsStatus.ps1)

```powershell
# Get-PawDefenderLocalExclusionsStatus.ps1
$Pref = Get-MpPreference
$Reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableLocalAdminMerge" -ErrorAction SilentlyContinue
$RegHide = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "HideExclusionsFromLocalAdmins" -ErrorAction SilentlyContinue
$RegConfig = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Name "DisableLocalAdminConfiguration" -ErrorAction SilentlyContinue
if (($Pref.DisableLocalAdminMerge -eq $true -or ($Reg -and $Reg.DisableLocalAdminMerge -eq 1)) -and
    ($RegHide -and $RegHide.HideExclusionsFromLocalAdmins -eq 1) -and
    ($RegConfig -and $RegConfig.DisableLocalAdminConfiguration -eq 1)) {
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
