# [REQ-END-156] User Profile: Command Processor Batch File Locking for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Microsoft\Command Processor\LockBatchFilesWhenInUse` = `1` (DWord)


---

## Rationale
Locking batch scripts when executing prevents attackers or concurrent processes from rewriting script lines on-the-fly, neutralizing dynamic code modification hijacks.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SOFTWARE\Microsoft\Command Processor\LockBatchFilesWhenInUse` = `1` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditLockbatchfiles.ps1](../implementation_scripts/Configure-EndAuditLockbatchfiles.ps1)

```powershell
# Configure-EndAuditLockbatchfiles.ps1
Write-Host "Enforcing System Mitigation control: lock-batch-files..." -ForegroundColor Cyan

# Set Registry value: LockBatchFilesWhenInUse
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Command Processor")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -Value 1 -Type DWord -Force
Write-Host "    Enforced LockBatchFilesWhenInUse = 1" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditLockbatchfilesStatus.ps1](../audit_scripts/Get-EndAuditLockbatchfilesStatus.ps1)

```powershell
# Get-EndAuditLockbatchfilesStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: LockBatchFilesWhenInUse
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Command Processor" -Name "LockBatchFilesWhenInUse" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LockBatchFilesWhenInUse -ne 1) {
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
* **ANSSI Active Directory Hardening Guide**: Client security baselines
* **CIS Windows 10/11 Client Benchmark**: Section 18.9 (Administrative Templates: System \ Mitigations) and Registry restrictions
