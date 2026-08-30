# [REQ-DC-140] Audit Policy: Directory Service Access Auditing on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**: `Computer Configuration\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies`
  * Subcategory: `Directory Service Changes` -> `Success and Failure`
  * Subcategory: `Directory Service Access` -> `Success and Failure`


---

## Rationale
Auditing Directory Service changes captures creations, modifications, and deletions of Active Directory objects, providing an essential trail for monitoring structural domain modifications.

Key security telemetry enabled by these subcategories includes:
1. **Shadow Credentials Detection (Event ID 5136)**: Placing a System Access Control List (SACL) on the `msDS-KeyCredentialLink` attribute across user and computer objects combined with `Directory Service Changes` auditing generates Event ID `5136` whenever an attacker attempts to inject raw X.509 certificate credentials (`pywhisker`, `PKINITtools`) to gain Kerberos PKINIT persistence or account takeover.
2. **DCSync & Replication Rights Auditing (Event ID 4662)**: Auditing `Directory Service Access` with SACLs placed on the Domain Root container generates Event ID `4662` when an attacker or unauthorized identity attempts DRSUAPI replication calls (`DS-Replication-Get-Changes-All`).
3. **Privileged Group & ACL Tampering**: Provides immediate visibility into unauthorized modifications to administrative groups (`Domain Admins`, `Enterprise Admins`, `DnsAdmins`) and `adminSDHolder` permission descriptors.

---

## Legacy Impact & Compatibility
* **Event Log Volume**: Verify that the local Security Event Log size is set to a minimum of 1GB on Domain Controllers to prevent rapid log rollover.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Configure Advanced Audit Policy subcategory settings matching:
   * Subcategory: `Directory Service Changes` -> `Success and Failure`
   * Subcategory: `Directory Service Access` -> `Success and Failure`
2. Configure Active Directory SACLs on sensitive containers:
   * To audit Shadow Credentials, open `ADSI Edit` (`adsiedit.msc`), navigate to target organizational units (e.g. `OU=Tier0,DC=corp,DC=local`), right-click -> **Properties** -> **Security** -> **Advanced** -> **Auditing** tab. Add an audit entry for `Everyone` covering `Write msDS-KeyCredentialLink` (Type: `All`).


---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcAuditDsaccess.ps1](../implementation_scripts/Configure-DcAuditDsaccess.ps1)

```powershell
# Configure-DcAuditDsaccess.ps1
Write-Host "Applying Audit Policy category: ds-access..." -ForegroundColor Cyan

# Set Audit Subcategory: Directory Service Changes
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Changes`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Changes to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Changes. Exit Code: $($Process.ExitCode)"
}

# Set Audit Subcategory: Directory Service Access
$Process = Start-Process auditpol -ArgumentList "/set /subcategory:`"Directory Service Access`" /success:enable /failure:enable" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "    Enforced subcategory Directory Service Access to Success and Failure" -ForegroundColor Green
} else {
    Write-Error "    Failed to configure subcategory Directory Service Access. Exit Code: $($Process.ExitCode)"
}


```

*To audit the hardening status:*
[Download Script: Get-DcAuditDsaccessStatus.ps1](../audit_scripts/Get-DcAuditDsaccessStatus.ps1)

```powershell
# Get-DcAuditDsaccessStatus.ps1
$script:Vulnerable = $false

# Audit Subcategory: Directory Service Changes
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Changes" /r
if ($RawOutput -notmatch ",Directory Service Changes,.*,(Success and Failure|Success & Failure)") {
    $script:Vulnerable = $true
}

# Audit Subcategory: Directory Service Access
$RawOutput = auditpol.exe /get /subcategory:"Directory Service Access" /r
if ($RawOutput -notmatch ",Directory Service Access,.*,(Success and Failure|Success & Failure)") {
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
* **ANSSI Active Directory Hardening Guide**: Recommendation R48
* **CIS Windows Server Benchmark**: Section 9 (Audit Policy)
