# [REQ-PAW-136] Audit Policy: Object Access Auditing for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Handle Manipulation` -> `Success and Failure`
  * Subcategory: `Registry` -> `Success and Failure`
  * Subcategory: `File Share` -> `Success and Failure`
  * Subcategory: `Detailed File Share` -> `Failure`
  * Subcategory: `Other Object Access Events` -> `Success and Failure`


---

## Rationale
Auditing object access (files, registry keys, and shares) helps monitor unauthorized modifications to system configuration files and access to restricted shares.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Ensure the local Security Event Log is sized to at least 512MB to accommodate the audit stream.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Subcategory: `Handle Manipulation` -> `Success and Failure`
  * Subcategory: `Registry` -> `Success and Failure`
  * Subcategory: `File Share` -> `Success and Failure`
  * Subcategory: `Detailed File Share` -> `Failure`
  * Subcategory: `Other Object Access Events` -> `Success and Failure`


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditObjectaccess.ps1](../implementation_scripts/Configure-PawAuditObjectaccess.ps1)

```powershell
# Configure-PawAuditObjectaccess.ps1
Write-Host "Applying Audit Policy category: object-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Handle Manipulation
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Handle Manipulation`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Handle Manipulation to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Handle Manipulation. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Registry
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Registry`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Registry to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Registry. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: File Share
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"File Share`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory File Share to Success and Failure" -ForegroundColor Green
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

# Set Audit Subcategory: Other Object Access Events
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Other Object Access Events`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Other Object Access Events to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Other Object Access Events. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-PawAuditObjectaccessStatus.ps1](../audit_scripts/Get-PawAuditObjectaccessStatus.ps1)

```powershell
# Get-PawAuditObjectaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Handle Manipulation
$RawOutput = auditpol.exe /get /subcategory:"Handle Manipulation" /r
if ($RawOutput -notmatch ",Handle Manipulation,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Registry
$RawOutput = auditpol.exe /get /subcategory:"Registry" /r
if ($RawOutput -notmatch ",Registry,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: File Share
$RawOutput = auditpol.exe /get /subcategory:"File Share" /r
if ($RawOutput -notmatch ",File Share,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Detailed File Share
$RawOutput = auditpol.exe /get /subcategory:"Detailed File Share" /r
if ($RawOutput -notmatch ",Detailed File Share,.*,Failure") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Other Object Access Events
$RawOutput = auditpol.exe /get /subcategory:"Other Object Access Events" /r
if ($RawOutput -notmatch ",Other Object Access Events,.*,(Success and Failure|Success & Failure)") {
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
