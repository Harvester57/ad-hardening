# [REQ-PAW-142] User Profile: Address Space Layout Randomization (ASLR) Image Relocation for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImages` = `4294967295` (DWord)


---

## Rationale
Enforcing Address Space Layout Randomization (ASLR) image relocation (MoveImages) forces all dynamic modules to relocate, neutralizing hardcoded ROP payload chains.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\MoveImages` = `4294967295` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditAslrrelocation.ps1](../implementation_scripts/Configure-PawAuditAslrrelocation.ps1)

```powershell
# Configure-PawAuditAslrrelocation.ps1
Write-Host "Enforcing System Mitigation control: aslr-relocation..." -ForegroundColor Cyan

# Set Registry value: MoveImages
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 4294967295 -Type DWord -Force
Write-Host "    Enforced MoveImages = 4294967295" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditAslrrelocationStatus.ps1](../audit_scripts/Get-PawAuditAslrrelocationStatus.ps1)

```powershell
# Get-PawAuditAslrrelocationStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: MoveImages
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.MoveImages -ne 4294967295) {
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
