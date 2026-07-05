# [REQ-DC-139] Audit Policy: Detailed Tracking Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Process Creation` -> `Success and Failure`
  * Subcategory: `DPAPI Activity` -> `Success and Failure`
  * Subcategory: `PNP Activity` -> `Success`


---

## Rationale
Detailed tracking records process creations and device arrivals to ensure EDR/SIEM visibility into executable command lines and hardware plug events.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Process Creation` -> `Success and Failure`
  * Subcategory: `DPAPI Activity` -> `Success and Failure`
  * Subcategory: `PNP Activity` -> `Success`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditDetailedtracking.ps1](../implementation_scripts/Configure-DcAuditDetailedtracking.ps1)

```powershell
# Configure-DcAuditDetailedtracking.ps1
Write-Host "Applying Audit Policy category: detailed-tracking..." -ForegroundColor Cyan

# Set Audit Subcategory: Process Creation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Process Creation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Process Creation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Process Creation. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: DPAPI Activity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"DPAPI Activity`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory DPAPI Activity to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory DPAPI Activity. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: PNP Activity
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"PNP Activity`" /success:enable /failure:disable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory PNP Activity to Success" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory PNP Activity. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditDetailedtrackingStatus.ps1](../audit_scripts/Get-DcAuditDetailedtrackingStatus.ps1)

```powershell
# Get-DcAuditDetailedtrackingStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Process Creation
$RawOutput = auditpol.exe /get /subcategory:"Process Creation" /r
if ($RawOutput -notmatch ",Process Creation,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: DPAPI Activity
$RawOutput = auditpol.exe /get /subcategory:"DPAPI Activity" /r
if ($RawOutput -notmatch ",DPAPI Activity,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: PNP Activity
$RawOutput = auditpol.exe /get /subcategory:"PNP Activity" /r
if ($RawOutput -notmatch ",PNP Activity,.*,Success") {
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
