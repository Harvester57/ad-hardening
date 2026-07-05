# [REQ-PAW-130] Audit Policy: Advanced Audit Policy Overrides for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs)
* **Operating Systems**: Windows 10/11 Enterprise

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
* **Event Log Volume**: Ensure the local Security Event Log is sized to at least 512MB to accommodate the audit stream.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory or registry override preferences matching:
  * Registry: `HKLM\System\CurrentControlSet\Control\Lsa\ SCENoApplyLegacyAuditPolicy` = `1` (DWord)
  * Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\ LogLevel` = `0` (DWord)


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditAuditoverride.ps1](../implementation_scripts/Configure-PawAuditAuditoverride.ps1)

```powershell
# Configure-PawAuditAuditoverride.ps1
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
[Download Script: Get-PawAuditAuditoverrideStatus.ps1](../audit_scripts/Get-PawAuditAuditoverrideStatus.ps1)

```powershell
# Get-PawAuditAuditoverrideStatus.ps1
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
