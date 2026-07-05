# [REQ-DC-143] Audit Policy: Policy Change Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Policy Change` -> `Success and Failure`
  * Subcategory: `Authentication Policy Change` -> `Success`
  * Subcategory: `Authorization Policy Change` -> `Success`
  * Subcategory: `MPSSVC Rule-Level Policy Change` -> `Success and Failure`
  * Subcategory: `Other Policy Change Events` -> `Failure`


---

## Rationale
Auditing policy changes tracks attempts to modify authorization policies, auditing configuration changes, or firewall rule alterations to hide adversarial tracks.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Policy Change` -> `Success and Failure`
  * Subcategory: `Authentication Policy Change` -> `Success`
  * Subcategory: `Authorization Policy Change` -> `Success`
  * Subcategory: `MPSSVC Rule-Level Policy Change` -> `Success and Failure`
  * Subcategory: `Other Policy Change Events` -> `Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditPolicychange.ps1](../implementation_scripts/Configure-DcAuditPolicychange.ps1)

```powershell
# Configure-DcAuditPolicychange.ps1
Write-Host "Applying Audit Policy category: policy-change..." -ForegroundColor Cyan

# Set Audit Subcategory: Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Policy Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Policy Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Authentication Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Authentication Policy Change`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Authentication Policy Change to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Authentication Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Authorization Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Authorization Policy Change`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Authorization Policy Change to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Authorization Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: MPSSVC Rule-Level Policy Change
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"MPSSVC Rule-Level Policy Change`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory MPSSVC Rule-Level Policy Change to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory MPSSVC Rule-Level Policy Change. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Other Policy Change Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Policy Change Events`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Policy Change Events to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Policy Change Events. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditPolicychangeStatus.ps1](../audit_scripts/Get-DcAuditPolicychangeStatus.ps1)

```powershell
# Get-DcAuditPolicychangeStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Policy Change" /r
if ($RawOutput -notmatch ",Policy Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Authentication Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Authentication Policy Change" /r
if ($RawOutput -notmatch ",Authentication Policy Change,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Authorization Policy Change
$RawOutput = auditpol.exe /get /subcategory:"Authorization Policy Change" /r
if ($RawOutput -notmatch ",Authorization Policy Change,.*,Success") {
    $script:Vulnerable = $true
}

# Audit Subcategory: MPSSVC Rule-Level Policy Change
$RawOutput = auditpol.exe /get /subcategory:"MPSSVC Rule-Level Policy Change" /r
if ($RawOutput -notmatch ",MPSSVC Rule-Level Policy Change,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Policy Change Events
$RawOutput = auditpol.exe /get /subcategory:"Other Policy Change Events" /r
if ($RawOutput -notmatch ",Other Policy Change Events,.*,Failure") {
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
