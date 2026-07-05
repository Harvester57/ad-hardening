# [REQ-END-147] Audit Policy: Object Access Auditing for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Registry` -> `Failure`
  * Subcategory: `File Share` -> `Failure`
  * Subcategory: `Detailed File Share` -> `Failure`
  * Subcategory: `Handle Manipulation` -> `Failure`


---

## Rationale
Auditing object access (files, registry keys, and shares) helps monitor unauthorized modifications to system configuration files and access to restricted shares.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Registry` -> `Failure`
  * Subcategory: `File Share` -> `Failure`
  * Subcategory: `Detailed File Share` -> `Failure`
  * Subcategory: `Handle Manipulation` -> `Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditObjectaccess.ps1](../implementation_scripts/Configure-EndAuditObjectaccess.ps1)

```powershell
# Configure-EndAuditObjectaccess.ps1
Write-Host "Applying Audit Policy category: object-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Registry
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Registry`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Registry to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Registry. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: File Share
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"File Share`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory File Share to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory File Share. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Detailed File Share
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Detailed File Share`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Detailed File Share to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Detailed File Share. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Handle Manipulation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Handle Manipulation`" /success:disable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Handle Manipulation to Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Handle Manipulation. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-EndAuditObjectaccessStatus.ps1](../audit_scripts/Get-EndAuditObjectaccessStatus.ps1)

```powershell
# Get-EndAuditObjectaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Registry
$RawOutput = auditpol.exe /get /subcategory:"Registry" /r
if ($RawOutput -notmatch ",Registry,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: File Share
$RawOutput = auditpol.exe /get /subcategory:"File Share" /r
if ($RawOutput -notmatch ",File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Detailed File Share
$RawOutput = auditpol.exe /get /subcategory:"Detailed File Share" /r
if ($RawOutput -notmatch ",Detailed File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Handle Manipulation
$RawOutput = auditpol.exe /get /subcategory:"Handle Manipulation" /r
if ($RawOutput -notmatch ",Handle Manipulation,.*,Failure") {
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
