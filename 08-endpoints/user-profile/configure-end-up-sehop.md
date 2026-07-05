# [REQ-END-151] User Profile: Structured Exception Handling Overwrite Protection (SEHOP) for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` = `0` (DWord)


---

## Rationale
Structured Exception Handling Overwrite Protection (SEHOP) detects and thwarts exploits targeting structured exception handler corruption, a common stack exploitation technique.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` = `0` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditSehop.ps1](../implementation_scripts/Configure-EndAuditSehop.ps1)

```powershell
# Configure-EndAuditSehop.ps1
Write-Host "Enforcing System Mitigation control: sehop..." -ForegroundColor Cyan

# Set Registry value: DisableExceptionChainValidation
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force
Write-Host "    Enforced DisableExceptionChainValidation = 0" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditSehopStatus.ps1](../audit_scripts/Get-EndAuditSehopStatus.ps1)

```powershell
# Get-EndAuditSehopStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: DisableExceptionChainValidation
$RegVal = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.DisableExceptionChainValidation -ne 0) {
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
