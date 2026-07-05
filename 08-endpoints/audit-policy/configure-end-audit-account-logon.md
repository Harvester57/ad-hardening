# [REQ-END-142] Audit Policy: Account Logon Auditing for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Credential Validation` -> `Success and Failure`


---

## Rationale
Auditing account logon events captures authentication requests processed by the local system or the domain controller, which is critical for identifying Kerberoasting, NTLM relaying, and brute-force attempts.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Credential Validation` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditAccountlogon.ps1](../implementation_scripts/Configure-EndAuditAccountlogon.ps1)

```powershell
# Configure-EndAuditAccountlogon.ps1
Write-Host "Applying Audit Policy category: account-logon..." -ForegroundColor Cyan

# Set Audit Subcategory: Credential Validation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Credential Validation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Credential Validation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Credential Validation. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-EndAuditAccountlogonStatus.ps1](../audit_scripts/Get-EndAuditAccountlogonStatus.ps1)

```powershell
# Get-EndAuditAccountlogonStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Credential Validation
$RawOutput = auditpol.exe /get /subcategory:"Credential Validation" /r
if ($RawOutput -notmatch ",Credential Validation,.*,(Success and Failure|Success & Failure)") {
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
