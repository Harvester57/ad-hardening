# [REQ-END-158] User Profile: Trusted Root Store Protected Roots Certificate Restriction for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags` = `1` (DWord)


---

## Rationale
Restricts users from installing root certificates into the trusted root store, preventing root CA hijack actions and man-in-the-middle proxy injection attacks.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots\Flags` = `1` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditProtectedroots.ps1](../implementation_scripts/Configure-EndAuditProtectedroots.ps1)

```powershell
# Configure-EndAuditProtectedroots.ps1
Write-Host "Enforcing System Mitigation control: protected-roots..." -ForegroundColor Cyan

# Set Registry value: Flags
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -Value 1 -Type DWord -Force
Write-Host "    Enforced Flags = 1" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditProtectedrootsStatus.ps1](../audit_scripts/Get-EndAuditProtectedrootsStatus.ps1)

```powershell
# Get-EndAuditProtectedrootsStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: Flags
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\Root\ProtectedRoots" -Name "Flags" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.Flags -ne 1) {
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
