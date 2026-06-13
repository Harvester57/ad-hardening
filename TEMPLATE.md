# [REQ-XXX-000] [Short, Clear Title of the Requirement]

## Target Scope
* **Applicable Systems**: [e.g., Domain Controllers, Member Servers, Tier 2 Clients (Windows 10/11)]
* **Operating Systems**: [e.g., Windows Server 2016, Windows 10 Enterprise (1809+)]

---

## Implementation Details
* **Priority**: [High / Medium / Low] (Based on criticality, ease of exploitation, and ANSSI/CIS recommendations)
* **GPO Path / Registry Location**: [e.g., Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options]

---

## Rationale
[Provide a comprehensive, detailed explanation of why this control is needed. Describe:
1. The threat vector or vulnerability being mitigated (e.g., credential harvesting, man-in-the-middle spoofing, lateral movement).
2. The specific security benefits this control introduces.
3. How this control contributes to the defense-in-depth posture of the AD directory services.]

---

## Legacy Impact & Compatibility
[Describe the potential side-effects of applying this setting, including:
1. Impact on legacy operating systems, applications, or authentication protocols (e.g., legacy NT4/NTLMv1 applications, older SMB shares).
2. Potential to break normal operations or services.
3. Any pre-requisites or baseline testing required before applying this control to the entire production environment.]

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Create a new GPO or edit an existing one (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `[Include full GPO path here, e.g., Computer Configuration\Policies\...]`
4. Configure the following setting:
   * **Policy**: `[Policy Name]`
   * **Setting**: `[Setting value, e.g., Enabled / Disabled / 5]`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: [Name-Of-Script].ps1](implementation_scripts/[Name-Of-Script].ps1)

```powershell
# [Name-Of-Script].ps1
# Description: [Brief description of what the script configures]

# Define registry/service parameters
$RegPath = "HKLM:\System\CurrentControlSet\..."
$ValueName = "..."
$ValueData = 1 # [Specify type and data]

Write-Host "Applying hardening requirement: [Requirement Name]..." -ForegroundColor Cyan

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

Set-ItemProperty -Path $RegPath -Name $ValueName -Value $ValueData -Type DWord
Write-Host "Hardening applied successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: [Audit-Script-Name].ps1](audit_scripts/[Audit-Script-Name].ps1)

```powershell
# [Audit-Script-Name].ps1
# Check current configuration state
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\..." -Name "..."
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: [e.g., Recommendation R19 (LDAP Signing)]
* **CIS Benchmark**: [e.g., CIS Windows Server 2016 Benchmark v2.0.0 - Section 2.3.7.4]
* **Microsoft Security Baseline Focus**: [e.g., Member Server Baseline - LDAP Security]
* **Other Reference**: [e.g., CVE-2021-36934 (PrintNightmare mitigation info)]
