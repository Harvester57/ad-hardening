# [REQ-PAW-146] User Profile: Time-Travel Debugging (TTD) Recording Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Registry Settings**:
  * Registry: `HKLM\SOFTWARE\Microsoft\TTD\RecordingPolicy` = `2` (DWord)


---

## Rationale
Disables and locks down user-mode Time-Travel Debugging (TTD) traces, preventing local adversaries from capturing memory dumps and private cryptographic structures from administrative processes.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricts legacy application hooks or diagnostic modes. Ensure testing in a representative staging environment prior to wide deployment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Deploy the following Registry settings using Group Policy Preferences (Registry Extension):
  * Registry: `HKLM\SOFTWARE\Microsoft\TTD\RecordingPolicy` = `2` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditTtdrecording.ps1](../implementation_scripts/Configure-PawAuditTtdrecording.ps1)

```powershell
# Configure-PawAuditTtdrecording.ps1
Write-Host "Enforcing System Mitigation control: ttd-recording..." -ForegroundColor Cyan

# Set Registry value: RecordingPolicy
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\TTD")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -Value 2 -Type DWord -Force
Write-Host "    Enforced RecordingPolicy = 2" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-PawAuditTtdrecordingStatus.ps1](../audit_scripts/Get-PawAuditTtdrecordingStatus.ps1)

```powershell
# Get-PawAuditTtdrecordingStatus.ps1
$script:Vulnerable = $false

# Audit Registry value: RecordingPolicy
$RegVal = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\TTD" -Name "RecordingPolicy" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.RecordingPolicy -ne 2) {
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
