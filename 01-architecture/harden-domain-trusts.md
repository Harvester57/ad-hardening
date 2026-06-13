# [REQ-ARCH-006] Harden Active Directory Domain Trusts

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory trust object attributes (`msDS-TrustSettings` / `trustAttributes` on trusted domain objects)

---

## Rationale
Active Directory trust relationships permit authentication and resource access across domain or forest boundaries. However, weak trust configurations can serve as transit routes for attackers to compromise trusting domains.

Specifically:
1. **SID History**: Enabling SID History allows users from a trusted forest to present security identifiers (SIDs) from other domains, bypass SID filtering, and potentially impersonate high-privilege administrators in the trusting forest. Disabling SID History on external/forest trusts prevents this path of escalation.
2. **SID Filtering / Quarantine**: Enabling Quarantine (SID Filtering) on external trusts ensures that the trusting domain filters out unauthorized SIDs presented in authorization packets, restricting access only to SIDs originating from the trusted domain itself.
3. **Kerberos TGT Delegation**: If TGT delegation is allowed on inbound trusts, a user authenticating from the trusted forest to a service in the trusting domain can have their Kerberos Ticket Granting Ticket (TGT) delegated to that service. If that service or host is compromised, the attacker can harvest the user's TGT and impersonate them. Blocking TGT delegation is critical to prevent credential exposure.
4. **Selective Authentication**: Enforcing selective authentication restricts cross-forest access, allowing administrators to explicitly define which users/groups from the trusted forest can authenticate to specific resources in the trusting forest.

---

## Legacy Impact & Compatibility
* **Operational Disruption**: Disabling SID History may disrupt access for users who migrated from old domains but still rely on legacy SIDs for resource permissions. Ensure that all migrated resources have updated Access Control Lists (ACLs) before disabling SID History.
* **Authentication Failure**: Enforcing selective authentication will block all cross-forest access by default until explicit "Allowed to Authenticate" permissions are configured on computer objects for target external security groups.

---

## Implementation Steps

### Option A: Active Directory Domains and Trusts GUI Configuration

1. Open **Active Directory Domains and Trusts** (`domain.msc`) on a Domain Controller.
2. Right-click the trusting domain and select **Properties**.
3. Select the **Trusts** tab.
4. Under either **Domains that trust this domain (Inbound)** or **Domains trusted by this domain (Outbound)**, select the target trust and click **Properties**.
5. Configure selective authentication:
   * Select the **Authentication** tab.
   * Change the option from **Forest-wide authentication** to **Selective authentication**.
6. Enforce SID filtering and quarantine rules (usually performed automatically when establishing external trusts).

---

### Option B: PowerShell & netdom Configuration (Remediation / Non-GPO)

Run the following script block to audit and harden trust relationships. The `netdom` utility is used to query and apply the trust settings.

[Download Script: Set-ADTrustHardening.ps1](implementation_scripts/Set-ADTrustHardening.ps1)

```powershell
# Set-ADTrustHardening.ps1
# Description: Hardens trust relationships by disabling SID History and TGT Delegation, and enabling Quarantine.

Write-Host "Applying hardening requirement: Harden Active Directory Domain Trusts..." -ForegroundColor Cyan

# Set target trust variables (replace with your domain names)
$TrustingDomain = "corp.local"
$TrustedDomain = "partner.local"

# 1. Disable SID History on Forest/External Trust
Write-Host "Disabling SID History on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /EnableSIDHistory:no

# 2. Enable Quarantine (SID Filtering) on External Domain Trust
Write-Host "Enabling Quarantine on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /Quarantine:yes

# 3. Disable TGT Delegation over Inbound Trust
Write-Host "Disabling Kerberos TGT Delegation on trust from $($TrustingDomain) to $($TrustedDomain)..." -ForegroundColor White
netdom trust $TrustingDomain /domain:$TrustedDomain /EnableTGTDelegation:no

Write-Host "Trust hardening commands executed." -ForegroundColor Green
```

*To verify the trust configuration state:*
[Download Script: Get-ADTrustStatus.ps1](audit_scripts/Get-ADTrustStatus.ps1)

```powershell
# Get-ADTrustStatus.ps1
# Description: Audits trust attributes and configuration settings.

Import-Module ActiveDirectory

Write-Host "--- Auditing Trust Relationships ---" -ForegroundColor Cyan

$Trusts = Get-ADTrust -Filter * -Properties *

if ($Trusts) {
    foreach ($Trust in $Trusts) {
        Write-Host "[+] Trust Name: $($Trust.Name)" -ForegroundColor Green
        Write-Host "    - Trust Type: $($Trust.TrustType)" -ForegroundColor White
        Write-Host "    - Direction: $($Trust.TrustDirection)" -ForegroundColor White
        Write-Host "    - Selective Authentication: $($Trust.SelectiveAuthentication)" -ForegroundColor White
        Write-Host "    - Disallow Transitivity: $($Trust.DisallowTransitivity)" -ForegroundColor White
        
        # Verify specific settings using netdom query
        Write-Host "    - netdom Configuration Details:" -ForegroundColor White
        netdom trust $Trust.Source /domain:$Trust.Target /Query
    }
} else {
    Write-Host "[-] No trust relationships found in the domain." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations R24, R25+, R26 (Section 3.2.3)
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 8 (Page 34), Section 4.e (Page 27)
* **Microsoft Security Guidance**: Security Considerations for Trusts
