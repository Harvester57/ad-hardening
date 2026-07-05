# [REQ-DC-141] Audit Policy: Logon and Logoff Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Logon` -> `Success and Failure`
  * Subcategory: `Logoff` -> `Success`
  * Subcategory: `Special Logon` -> `Success and Failure`
  * Subcategory: `Account Lockout` -> `Success and Failure`
  * Subcategory: `Other Logon/Logoff Events` -> `Success and Failure`


---

## Rationale
Auditing logon/logoff events monitors administrative session states, special elevations, and failed logon attempts, which is critical for finding unauthorized remote access or lateral movement.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Logon` -> `Success and Failure`
  * Subcategory: `Logoff` -> `Success`
  * Subcategory: `Special Logon` -> `Success and Failure`
  * Subcategory: `Account Lockout` -> `Success and Failure`
  * Subcategory: `Other Logon/Logoff Events` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditLogonlogoff.ps1](../implementation_scripts/Configure-DcAuditLogonlogoff.ps1)

```powershell
# Configure-DcAuditLogonlogoff.ps1
Write-Host "Applying Audit Policy category: logon-logoff..." -ForegroundColor Cyan

# Set Audit Subcategory: Logon
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Logon`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Logon to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Logon. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Logoff
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Logoff`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Logoff to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Logoff. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Special Logon
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Special Logon`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Special Logon to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Special Logon. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Account Lockout
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Account Lockout`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Account Lockout to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Account Lockout. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Logon/Logoff Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Logon/Logoff Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Logon/Logoff Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Logon/Logoff Events. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditLogonlogoffStatus.ps1](../audit_scripts/Get-DcAuditLogonlogoffStatus.ps1)

```powershell
# Get-DcAuditLogonlogoffStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Logon
$RawOutput = auditpol.exe /get /subcategory:"Logon" /r
if ($RawOutput -notmatch ",Logon,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Logoff
$RawOutput = auditpol.exe /get /subcategory:"Logoff" /r
if ($RawOutput -notmatch ",Logoff,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Special Logon
$RawOutput = auditpol.exe /get /subcategory:"Special Logon" /r
if ($RawOutput -notmatch ",Special Logon,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Account Lockout
$RawOutput = auditpol.exe /get /subcategory:"Account Lockout" /r
if ($RawOutput -notmatch ",Account Lockout,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Logon/Logoff Events
$RawOutput = auditpol.exe /get /subcategory:"Other Logon/Logoff Events" /r
if ($RawOutput -notmatch ",Other Logon/Logoff Events,.*,(Success and Failure|Success & Failure)") {
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
