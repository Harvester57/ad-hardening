# [REQ-LOG-001] Configure Advanced Security Audit Policies

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Client Workstations
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise

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
Standard Windows security event logging is basic and fails to capture critical event vectors, leading to visibility gaps during compromises. Enforcing refined subcategory audit policies ensures detailed Success and Failure logs for logon attempts, privilege use, process creations, and registry modifications without overloading log stores. 

This requirement acts as the primary logging baseline, enforcing category overrides and linking to profile-specific submodules matching each system's security tier.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Set local Security Event Log size to a minimum of 512MB to prevent premature rollover of security auditing data.

---

## Modular Profile Audit Policies
This logging requirement is split into profile-specific advanced audit submodules mapping to each system's security tier:
* **[REQ-DC-135 - Configure Advanced Security Audit Policies for Domain Controllers](../02-domain-controllers/audit-policy/README.md)**
* **[REQ-PAW-129 - Configure Advanced Security Audit Policies for PAWs](../07-paws/audit-policy/README.md)**
* **[REQ-END-140 - Configure Advanced Security Audit Policies for Endpoints](../08-endpoints/audit-policy/README.md)**

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the corresponding baseline GPO (e.g. `GPO_Hardening_Baseline`).
3. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings`
   * **Setting**: `Enabled`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-AdvancedAuditPolicies.ps1](implementation_scripts/Configure-AdvancedAuditPolicies.ps1)

```powershell
# Configure-AdvancedAuditPolicies.ps1
# Description: Enforces Advanced Audit Policy Overrides registry value.

$RegPath = "reg:\HKLM\System\CurrentControlSet\Control\Lsa"
$ValueName = "SCENoApplyLegacyAuditPolicy"

Write-Host "Enforcing Advanced Security Audit Policies override settings..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value 1 -Type DWord -Force
Write-Host "Advanced Audit Policy overrides enforced successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-AdvancedAuditPoliciesStatus.ps1](audit_scripts/Get-AdvancedAuditPoliciesStatus.ps1)

```powershell
# Get-AdvancedAuditPoliciesStatus.ps1
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
