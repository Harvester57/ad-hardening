# [REQ-DC-137] Audit Policy: Account Logon Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Kerberos Authentication Service` -> `Success and Failure`
  * Subcategory: `Kerberos Service Ticket Operations` -> `Success and Failure`
  * Subcategory: `Credential Validation` -> `Success and Failure`


---

## Rationale
Auditing account logon events captures authentication requests processed by the local system or the domain controller, which is critical for identifying Kerberoasting, NTLM relaying, and brute-force attempts.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Kerberos Authentication Service` -> `Success and Failure`
  * Subcategory: `Kerberos Service Ticket Operations` -> `Success and Failure`
  * Subcategory: `Credential Validation` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditAccountlogon.ps1](../implementation_scripts/Configure-DcAuditAccountlogon.ps1)

```powershell
# Configure-DcAuditAccountlogon.ps1
Write-Host "Applying Audit Policy category: account-logon..." -ForegroundColor Cyan

# Set Audit Subcategory: Kerberos Authentication Service
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Kerberos Authentication Service`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Kerberos Authentication Service to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Kerberos Authentication Service. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Kerberos Service Ticket Operations
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Kerberos Service Ticket Operations`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Kerberos Service Ticket Operations to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Kerberos Service Ticket Operations. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Credential Validation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Credential Validation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Credential Validation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Credential Validation. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditAccountlogonStatus.ps1](../audit_scripts/Get-DcAuditAccountlogonStatus.ps1)

```powershell
# Get-DcAuditAccountlogonStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Kerberos Authentication Service
$RawOutput = auditpol.exe /get /subcategory:"Kerberos Authentication Service" /r
if ($RawOutput -notmatch ",Kerberos Authentication Service,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Kerberos Service Ticket Operations
$RawOutput = auditpol.exe /get /subcategory:"Kerberos Service Ticket Operations" /r
if ($RawOutput -notmatch ",Kerberos Service Ticket Operations,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

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
* **ANSSI Active Directory Hardening Guide**: Recommendation R48
* **CIS Windows Server Benchmark**: Section 9 (Audit Policy)
