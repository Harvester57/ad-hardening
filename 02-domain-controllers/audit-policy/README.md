# [REQ-DC-135] Configure Advanced Security Audit Policies for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

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
Enforcing category overrides on Domain Controllers is a prerequisite to ensure that the refined audit subcategories (such as Directory Service Access, Kerberos operations, etc.) are correctly logged and not masked by basic legacy policies.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Ensure the Security log size is at least 1GB to prevent rollover.

---

## Submodule Requirements
The child policies under this parent requirement:
* **[REQ-DC-136 - Audit Policy: Advanced Audit Policy Overrides](configure-dc-audit-audit-override.md)**
* **[REQ-DC-137 - Audit Policy: Account Logon Auditing](configure-dc-audit-account-logon.md)**
* **[REQ-DC-138 - Audit Policy: Account Management Auditing](configure-dc-audit-account-management.md)**
* **[REQ-DC-139 - Audit Policy: Detailed Tracking Auditing](configure-dc-audit-detailed-tracking.md)**
* **[REQ-DC-140 - Audit Policy: Directory Service Access Auditing](configure-dc-audit-ds-access.md)**
* **[REQ-DC-141 - Audit Policy: Logon and Logoff Auditing](configure-dc-audit-logon-logoff.md)**
* **[REQ-DC-142 - Audit Policy: Object Access Auditing](configure-dc-audit-object-access.md)**
* **[REQ-DC-143 - Audit Policy: Policy Change Auditing](configure-dc-audit-policy-change.md)**
* **[REQ-DC-144 - Audit Policy: Privilege Use Auditing](configure-dc-audit-privilege-use.md)**
* **[REQ-DC-145 - Audit Policy: System Events Auditing](configure-dc-audit-system-events.md)**

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the following setting:
   * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditPoliciesParent.ps1](../implementation_scripts/Configure-DcAuditPoliciesParent.ps1)

```powershell
# Configure-DcAuditPoliciesParent.ps1
# Description: Enforces Advanced Audit Policy Overrides registry value.

$RegPath = "reg:\HKLM\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -Force
Write-Host "Enforced SCENoApplyLegacyAuditPolicy = 1 on Domain Controller" -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-DcAuditPoliciesParentStatus.ps1](../audit_scripts/Get-DcAuditPoliciesParentStatus.ps1)

```powershell
# Get-DcAuditPoliciesParentStatus.ps1
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
