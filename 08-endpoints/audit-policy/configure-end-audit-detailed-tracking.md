# [REQ-END-144] Audit Policy: Detailed Tracking Auditing for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

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
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Process Creation` -> `Success and Failure`
  * Subcategory: `DPAPI Activity` -> `Success and Failure`
  * Subcategory: `PNP Activity` -> `Success`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditDetailedtracking.ps1](../implementation_scripts/Configure-EndAuditDetailedtracking.ps1)

```powershell
# Configure-EndAuditDetailedtracking.ps1
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
[Download Script: Get-EndAuditDetailedtrackingStatus.ps1](../audit_scripts/Get-EndAuditDetailedtrackingStatus.ps1)

```powershell
# Get-EndAuditDetailedtrackingStatus.ps1
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
* **ANSSI Active Directory Hardening Guide**: Client auditing baselines
* **CIS Windows 10/11 Benchmark**: Section 17 (Advanced Audit Policy Configuration)
