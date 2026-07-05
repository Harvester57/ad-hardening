# [REQ-PAW-143] User Profile: Speculative Execution Mitigations (Spectre/Meltdown) for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride` = `72` (DWord)
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask` = `3` (DWord)


---

## Rationale
Enforces hardware-backed speculative execution mitigations (Spectre, Meltdown, MDS) to prevent side-channel leaks of sensitive kernel-space data.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride` = `72` (DWord)
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask` = `3` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditSpeculativemitigations.ps1](../implementation_scripts/Configure-PawAuditSpeculativemitigations.ps1)

```powershell
# Configure-PawAuditSpeculativemitigations.ps1
Write-Host "Enforcing System Mitigation control: speculative-mitigations..." -ForegroundColor Cyan

# Set Registry value: FeatureSettingsOverride
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Value 72 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverride = 72" -ForegroundColor Green

# Set Registry value: FeatureSettingsOverrideMask
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force
Write-Host "    Enforced FeatureSettingsOverrideMask = 3" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditSpeculativemitigationsStatus.ps1](../audit_scripts/Get-PawAuditSpeculativemitigationsStatus.ps1)

```powershell
# Get-PawAuditSpeculativemitigationsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: FeatureSettingsOverride
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverride -ne 72) {
    $script:Vulnerable = $true
}

# Audit Registry value: FeatureSettingsOverrideMask
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.FeatureSettingsOverrideMask -ne 3) {
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Client security baselines
* **CIS Windows 10/11 Client Benchmark**: Section 18.9 (Administrative Templates: System \ Mitigations) and Registry restrictions
