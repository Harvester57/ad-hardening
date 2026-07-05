# [REQ-PAW-141] User Profile: Directory Protection Mode for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode` = `1` (DWord)


---

## Rationale
Setting ProtectionMode to 1 restricts access to crucial system folders like System32, enforcing strict ACLs and protecting against write tampering.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\ProtectionMode` = `1` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditProtectionmode.ps1](../implementation_scripts/Configure-PawAuditProtectionmode.ps1)

```powershell
# Configure-PawAuditProtectionmode.ps1
Write-Host "Enforcing System Mitigation control: protection-mode..." -ForegroundColor Cyan

# Set Registry value: ProtectionMode
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord -Force
Write-Host "    Enforced ProtectionMode = 1" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditProtectionmodeStatus.ps1](../audit_scripts/Get-PawAuditProtectionmodeStatus.ps1)

```powershell
# Get-PawAuditProtectionmodeStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: ProtectionMode
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.ProtectionMode -ne 1) {
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
