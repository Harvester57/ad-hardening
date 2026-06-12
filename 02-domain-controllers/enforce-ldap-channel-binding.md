# Hardening Requirement: Enforce LDAP Channel Binding

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Domain controller: LDAP server channel binding token requirements`
  * **Setting**: `Always`
  * **Registry Location**: `HKLM\System\CurrentControlSet\Services\NTDS\Parameters` -> `LdapEnforceChannelBinding` = `2` (REG_DWORD)

---

## Rationale
Adversaries use credential relay attacks (such as NTLM relaying) to intercept authentication challenges and replay them to other network services. In a coercion attack (e.g., the PetitPotam technique), an attacker forces a Domain Controller to authenticate to a malicious listener using NTLM. The attacker then relays these credentials to Active Directory Certificate Services (ADCS) or an LDAPS server to issue administrative certificates or modify directory databases.

LDAP Channel Binding Tokens (CBT) mitigate these relay attacks. CBT establishes a cryptographic link between the transport-level security channel (TLS/SSL) and the application-level authentication protocol (SASL/NTLM/Kerberos). By requiring CBT verification on the LDAP server, the Domain Controller verifies that the authentication request originated from within the specific TLS channel used to send it. If an attacker attempts to relay credentials from a different session, the channel parameters will not match, and the Domain Controller will reject the authentication request.

---

## Legacy Impact & Compatibility
* **Client and Software Compatibility**: Enforcing Channel Binding requirements to `Always` (level 2) means that any LDAP client connecting over SSL/TLS (LDAPS on port 636 or LDAP startTLS on port 389) must support and submit CBT. Older Windows clients without security patches, third-party LDAP integration clients, Java-based applications, or Linux/Unix systems using outdated LDAP packages may fail to bind if they do not support channel binding.
* **Pre-requisite Patching**: Ensure that all clients and Domain Controllers have the latest security updates installed.
* **Audit and Phased Deployment**: Administrators can configure `LdapEnforceChannelBinding` to `1` (When Supported) during a testing phase. Event logs should be reviewed (specifically Directory Service Event ID 3039, which indicates client compatibility failures) before enforcing the setting to `2` (Always).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the GPO linked to the Domain Controllers Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Domain controller: LDAP server channel binding token requirements`
   * **Setting**: `Always`
5. Link the GPO to the Domain Controllers OU.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-LDAPChannelBinding.ps1](implementation_scripts/Configure-LDAPChannelBinding.ps1)

```powershell
# Configure-LDAPChannelBinding.ps1
# Description: Enforces LDAP Channel Binding Token requirements to Always.

Write-Host "Applying hardening requirement: Enforce LDAP Channel Binding..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -Value 2 -Type DWord
Write-Host "LDAP Channel Binding requirements set to 2 (Always)." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-LDAPChannelBindingStatus.ps1](audit_scripts/Get-LDAPChannelBindingStatus.ps1)

```powershell
# Get-LDAPChannelBindingStatus.ps1
# Description: Audits the LDAP Channel Binding Token configuration in the registry.

Write-Host "--- Auditing LDAP Channel Binding ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$ntdsReg = Get-ItemProperty -Path $regPath -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue

if ($ntdsReg) {
    $cbtVal = $ntdsReg.LdapEnforceChannelBinding
    if ($cbtVal -eq 2) {
        Write-Host "[+] LDAP Channel Binding is secure. LdapEnforceChannelBinding is set to $($cbtVal) (Always)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LdapEnforceChannelBinding is set to $($cbtVal) (Required: 2)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LdapEnforceChannelBinding registry value is missing. The system uses default settings (does not enforce CBT)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R20 (LDAP Channel Binding)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.3.2 (Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always')
* **Microsoft Security Advisory**: CVE-2017-8563 (LDAP Channel Binding security update details)
