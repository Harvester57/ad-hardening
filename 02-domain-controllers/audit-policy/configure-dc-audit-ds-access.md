# [REQ-DC-140] Audit Policy: Directory Service Access Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Directory Service Changes` -> `Success and Failure`
  * Subcategory: `Directory Service Access` -> `Success and Failure`


---

## Rationale
Auditing Directory Service changes captures creations, modifications, and deletions of Active Directory objects, providing an essential trail for monitoring structural domain modifications.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Directory Service Changes` -> `Success and Failure`
  * Subcategory: `Directory Service Access` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditDsaccess.ps1](../implementation_scripts/Configure-DcAuditDsaccess.ps1)

```powershell
# Configure-DcAuditDsaccess.ps1
Write-Host "Applying Audit Policy category: ds-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Directory Service Changes
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Changes`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Changes to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Changes. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Directory Service Access
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Access`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Access to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Access. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditDsaccessStatus.ps1](../audit_scripts/Get-DcAuditDsaccessStatus.ps1)

```powershell
# Get-DcAuditDsaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Directory Service Changes
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Changes" /r
if ($RawOutput -notmatch ",Directory Service Changes,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Directory Service Access
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Access" /r
if ($RawOutput -notmatch ",Directory Service Access,.*,(Success and Failure|Success & Failure)") {
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R48
* **CIS Windows Server Benchmark**: Section 9 (Audit Policy)
