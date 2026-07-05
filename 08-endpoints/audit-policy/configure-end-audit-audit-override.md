# [REQ-END-141] Audit Policy: Advanced Audit Policy Overrides for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Registry: `HKLM\System\CurrentControlSet\Control\Lsa\ SCENoApplyLegacyAuditPolicy` = `1` (DWord)
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\ LogLevel` = `0` (DWord)


---

## Rationale
Enforcing advanced audit policy overrides prevents legacy category settings from overriding refined subcategory policies, and disabling verbose Kerberos logging ensures that event logs are not flooded with diagnostic events.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Registry: `HKLM\System\CurrentControlSet\Control\Lsa\ SCENoApplyLegacyAuditPolicy` = `1` (DWord)
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\ LogLevel` = `0` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditAuditoverride.ps1](../implementation_scripts/Configure-EndAuditAuditoverride.ps1)

```powershell
# Configure-EndAuditAuditoverride.ps1
Write-Host "Applying Audit Policy category: audit-override..." -ForegroundColor Cyan

# Set Registry Override: SCENoApplyLegacyAuditPolicy
if (-not (Test-Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa")) { New-Item -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Force | Out-Null }
Set-ItemProperty -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord -Force
Write-Host "    Enforced SCENoApplyLegacyAuditPolicy = 1" -ForegroundColor Green

# Set Registry Override: LogLevel
if (-not (Test-Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters")) { New-Item -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Force | Out-Null }
Set-ItemProperty -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -Value 0 -Type DWord -Force
Write-Host "    Enforced LogLevel = 0" -ForegroundColor Green


```

*To audit the hardening status:*
[Download Script: Get-EndAuditAuditoverrideStatus.ps1](../audit_scripts/Get-EndAuditAuditoverrideStatus.ps1)

```powershell
# Get-EndAuditAuditoverrideStatus.ps1
$script:Vulnerable = $false

# Audit Registry: SCENoApplyLegacyAuditPolicy
$RegVal = Get-ItemProperty -Path "reg:\HKLM\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.SCENoApplyLegacyAuditPolicy -ne 1) {
    $script:Vulnerable = $true
}

# Audit Registry: LogLevel
$RegVal = Get-ItemProperty -Path "reg:\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" -Name "LogLevel" -ErrorAction SilentlyContinue
if (-not $RegVal -or $RegVal.LogLevel -ne 0) {
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
