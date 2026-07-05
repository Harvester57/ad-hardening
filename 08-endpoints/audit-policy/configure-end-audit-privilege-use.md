# [REQ-END-149] Audit Policy: Privilege Use Auditing for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Sensitive Privilege Use` -> `Success and Failure`


---

## Rationale
Auditing sensitive privilege use logs attempts by processes or users to exercise rights like ActAsPartOfTypeOperatingSystem or LoadDrivers, identifying potential privilege escalations.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Sensitive Privilege Use` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditPrivilegeuse.ps1](../implementation_scripts/Configure-EndAuditPrivilegeuse.ps1)

```powershell
# Configure-EndAuditPrivilegeuse.ps1
Write-Host "Applying Audit Policy category: privilege-use..." -ForegroundColor Cyan

# Set Audit Subcategory: Sensitive Privilege Use
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Sensitive Privilege Use`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Sensitive Privilege Use to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Sensitive Privilege Use. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-EndAuditPrivilegeuseStatus.ps1](../audit_scripts/Get-EndAuditPrivilegeuseStatus.ps1)

```powershell
# Get-EndAuditPrivilegeuseStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Sensitive Privilege Use
$RawOutput = auditpol.exe /get /subcategory:"Sensitive Privilege Use" /r
if ($RawOutput -notmatch ",Sensitive Privilege Use,.*,(Success and Failure|Success & Failure)") {
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
* **ANSSI Active Directory Hardening Guide**: Client auditing baselines
* **CIS Windows 10/11 Benchmark**: Section 17 (Advanced Audit Policy Configuration)
