# [REQ-END-140] Configure Advanced Security Audit Policies for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
  * **Setting**: `Enabled`
  * **Registry Location**: `HKLM\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy` = `1` (DWord)

---

## Rationale
Enforcing category overrides on client workstations is a prerequisite to ensure that the refined audit subcategories (such as Logon, Object Access, System Events, etc.) are correctly logged and not masked by basic legacy policies.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Ensure the Security log size is at least 512MB to prevent rollover.

---

## Submodule Requirements
The child policies under this parent requirement:
* **[REQ-END-141 - Audit Policy: Advanced Audit Policy Overrides for Endpoints](configure-end-audit-audit-override.md)**
* **[REQ-END-142 - Audit Policy: Account Logon Auditing for Endpoints](configure-end-audit-account-logon.md)**
* **[REQ-END-143 - Audit Policy: Account Management Auditing for Endpoints](configure-end-audit-account-management.md)**
* **[REQ-END-144 - Audit Policy: Detailed Tracking Auditing for Endpoints](configure-end-audit-detailed-tracking.md)**
* **[REQ-END-145 - Audit Policy: Logon and Logoff Auditing for Endpoints](configure-end-audit-logon-logoff.md)**
* **[REQ-END-146 - Audit Policy: Object Access Auditing for Endpoints](configure-end-audit-object-access.md)**
* **[REQ-END-147 - Audit Policy: Policy Change Auditing for Endpoints](configure-end-audit-policy-change.md)**
* **[REQ-END-148 - Audit Policy: Privilege Use Auditing for Endpoints](configure-end-audit-privilege-use.md)**
* **[REQ-END-149 - Audit Policy: System Events Auditing for Endpoints](configure-end-audit-system-events.md)**

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the following setting:
   * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-EndAuditPoliciesParent.ps1](../implementation_scripts/Configure-EndAuditPoliciesParent.ps1)

```powershell
# Configure-EndAuditPoliciesParent.ps1
# Description: Enforces Advanced Audit Policy Overrides registry value.

$RegPath = "reg:\HKLM\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -Force
Write-Host "Enforced SCENoApplyLegacyAuditPolicy = 1 on Endpoint" -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-EndAuditPoliciesParentStatus.ps1](../audit_scripts/Get-EndAuditPoliciesParentStatus.ps1)

```powershell
# Get-EndAuditPoliciesParentStatus.ps1
# Description: Audits the Advanced Audit Policy Overrides registry value.

$RegPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

$val = Get-ItemPropertyValue -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
if ($val -eq 1) {
    Write-Host "Advanced Security Audit Policy Overrides are correctly enabled." -ForegroundColor Green
} else {
    Write-Host "Advanced Security Audit Policy Overrides are disabled!" -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R48
* **CIS Benchmark**: Section 9 and 17
