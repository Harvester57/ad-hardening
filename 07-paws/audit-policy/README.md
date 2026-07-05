# [REQ-PAW-129] Configure Advanced Security Audit Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations
* **Operating Systems**: Windows 10/11 Enterprise

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
Enforcing category overrides on PAWs is a prerequisite to ensure that the refined audit subcategories (such as Logon, Object Access, System Events, etc.) are correctly logged and not masked by basic legacy policies.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Ensure the Security log size is at least 512MB to prevent rollover.

---

## Submodule Requirements
The child policies under this parent requirement:
* **[REQ-PAW-130 - Audit Policy: Advanced Audit Policy Overrides for PAWs](configure-paw-audit-audit-override.md)**
* **[REQ-PAW-131 - Audit Policy: Account Logon Auditing for PAWs](configure-paw-audit-account-logon.md)**
* **[REQ-PAW-132 - Audit Policy: Account Management Auditing for PAWs](configure-paw-audit-account-management.md)**
* **[REQ-PAW-133 - Audit Policy: Detailed Tracking Auditing for PAWs](configure-paw-audit-detailed-tracking.md)**
* **[REQ-PAW-134 - Audit Policy: Logon and Logoff Auditing for PAWs](configure-paw-audit-logon-logoff.md)**
* **[REQ-PAW-135 - Audit Policy: Object Access Auditing for PAWs](configure-paw-audit-object-access.md)**
* **[REQ-PAW-136 - Audit Policy: Policy Change Auditing for PAWs](configure-paw-audit-policy-change.md)**
* **[REQ-PAW-137 - Audit Policy: Privilege Use Auditing for PAWs](configure-paw-audit-privilege-use.md)**
* **[REQ-PAW-138 - Audit Policy: System Events Auditing for PAWs](configure-paw-audit-system-events.md)**

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the following setting:
   * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawAuditPoliciesParent.ps1](../implementation_scripts/Configure-PawAuditPoliciesParent.ps1)

```powershell
# Configure-PawAuditPoliciesParent.ps1
# Description: Enforces Advanced Audit Policy Overrides registry value.

$RegPath = "reg:\HKLM\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -Force
Write-Host "Enforced SCENoApplyLegacyAuditPolicy = 1 on PAW" -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-PawAuditPoliciesParentStatus.ps1](../audit_scripts/Get-PawAuditPoliciesParentStatus.ps1)

```powershell
# Get-PawAuditPoliciesParentStatus.ps1
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
