# [REQ-DC-145] Audit Policy: System Events Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `IPsec Driver` -> `Success and Failure`
  * Subcategory: `Other System Events` -> `Success and Failure`
  * Subcategory: `Security State Change` -> `Success and Failure`
  * Subcategory: `Security System Extension` -> `Success and Failure`
  * Subcategory: `System Integrity` -> `Success and Failure`


---

## Rationale
Auditing system security extensions, integrity violations, and driver arrivals monitors boot health and tampering of host security services.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `IPsec Driver` -> `Success and Failure`
  * Subcategory: `Other System Events` -> `Success and Failure`
  * Subcategory: `Security State Change` -> `Success and Failure`
  * Subcategory: `Security System Extension` -> `Success and Failure`
  * Subcategory: `System Integrity` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditSystemevents.ps1](../implementation_scripts/Configure-DcAuditSystemevents.ps1)

```powershell
# Configure-DcAuditSystemevents.ps1
Write-Host "Applying Audit Policy category: system-events..." -ForegroundColor Cyan

# Set Audit Subcategory: IPsec Driver
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"IPsec Driver`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory IPsec Driver to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory IPsec Driver. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other System Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other System Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other System Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other System Events. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security State Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security State Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security State Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security State Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security System Extension
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security System Extension`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security System Extension to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security System Extension. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: System Integrity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"System Integrity`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory System Integrity to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory System Integrity. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditSystemeventsStatus.ps1](../audit_scripts/Get-DcAuditSystemeventsStatus.ps1)

```powershell
# Get-DcAuditSystemeventsStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: IPsec Driver
$RawOutput = auditpol.exe /get /subcategory:"IPsec Driver" /r
if ($RawOutput -notmatch ",IPsec Driver,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other System Events
$RawOutput = auditpol.exe /get /subcategory:"Other System Events" /r
if ($RawOutput -notmatch ",Other System Events,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security State Change
$RawOutput = auditpol.exe /get /subcategory:"Security State Change" /r
if ($RawOutput -notmatch ",Security State Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security System Extension
$RawOutput = auditpol.exe /get /subcategory:"Security System Extension" /r
if ($RawOutput -notmatch ",Security System Extension,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: System Integrity
$RawOutput = auditpol.exe /get /subcategory:"System Integrity" /r
if ($RawOutput -notmatch ",System Integrity,.*,(Success and Failure|Success & Failure)") {
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
