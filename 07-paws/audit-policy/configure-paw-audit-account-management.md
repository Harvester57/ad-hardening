# [REQ-PAW-132] Audit Policy: Account Management Auditing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `User Account Management` -> `Success and Failure`
  * Subcategory: `Security Group Management` -> `Success and Failure`
  * Subcategory: `Computer Account Management` -> `Success and Failure`
  * Subcategory: `Other Account Management Events` -> `Success and Failure`


---

## Rationale
Auditing account management logs security principal modifications (creations, deletions, password resets, group modifications) to detect privilege escalation attempts on domain or local administrative groups.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Ensure the local Security Event Log is sized to at least 512MB to accommodate the audit stream.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `User Account Management` -> `Success and Failure`
  * Subcategory: `Security Group Management` -> `Success and Failure`
  * Subcategory: `Computer Account Management` -> `Success and Failure`
  * Subcategory: `Other Account Management Events` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditAccountmanagement.ps1](../implementation_scripts/Configure-PawAuditAccountmanagement.ps1)

```powershell
# Configure-PawAuditAccountmanagement.ps1
Write-Host "Applying Audit Policy category: account-management..." -ForegroundColor Cyan

# Set Audit Subcategory: User Account Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"User Account Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory User Account Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory User Account Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Security Group Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Security Group Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Security Group Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Security Group Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Computer Account Management
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Computer Account Management`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Computer Account Management to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Computer Account Management. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Account Management Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Account Management Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Account Management Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Account Management Events. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-PawAuditAccountmanagementStatus.ps1](../audit_scripts/Get-PawAuditAccountmanagementStatus.ps1)

```powershell
# Get-PawAuditAccountmanagementStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: User Account Management
$RawOutput = auditpol.exe /get /subcategory:"User Account Management" /r
if ($RawOutput -notmatch ",User Account Management,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Security Group Management
$RawOutput = auditpol.exe /get /subcategory:"Security Group Management" /r
if ($RawOutput -notmatch ",Security Group Management,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Computer Account Management
$RawOutput = auditpol.exe /get /subcategory:"Computer Account Management" /r
if ($RawOutput -notmatch ",Computer Account Management,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Account Management Events
$RawOutput = auditpol.exe /get /subcategory:"Other Account Management Events" /r
if ($RawOutput -notmatch ",Other Account Management Events,.*,(Success and Failure|Success & Failure)") {
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
