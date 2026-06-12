# Hardening Requirement: Enforce LDAP Server Signing

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Policy**: `Domain controller: LDAP server signing requirements`
  * **Setting**: `Require signing`
  * **Registry Location**: `HKLM\System\CurrentControlSet\Services\NTDS\Parameters` -> `LDAPServerIntegrity` = `2` (REG_DWORD)

---

## Rationale
Lightweight Directory Access Protocol (LDAP) traffic transmitted over cleartext (TCP port 389) without signing is vulnerable to eavesdropping and man-in-the-middle (MitM) attacks. An adversary in a position to intercept network traffic can inject malicious payload packets, modify directory responses, or perform session hijacking.

Enforcing LDAP signing ensures that the LDAP server (Domain Controller) rejects simple binds that are not encrypted or signed. It mandates data integrity verification via cryptographically secure signatures on the network packets. This directly mitigates the threat of LDAP relay and injection attacks, securing the communication path between directory clients and Domain Controllers.

---

## Legacy Impact & Compatibility
* **Client Compatibility**: Enforcing LDAP signing on Domain Controllers requires that all clients connecting via cleartext LDAP support and negotiate signing (e.g., SASL GSS-API). Simple LDAP binds that pass passwords in cleartext without SSL/TLS or signing will fail.
* **Non-Windows Systems**: Many third-party integrations, older Linux/Unix servers (running older SSSD or PAM LDAP modules), network appliances (e.g., printers, scanners, firewalls), and custom legacy applications do not support LDAP signing. These devices must be updated to support signing or reconfigured to use secure LDAP (LDAPS) over port 636.
* **Audit Phase**: Prior to enforcement, check directory service event logs (Event ID 2887 is logged every 24 hours indicating how many unsigned and cleartext LDAP binds occurred; Event ID 2889 can be enabled to identify the specific IP addresses and account names of clients performing unsigned binds).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the GPO linked to the Domain Controllers Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following setting:
   * **Policy**: `Domain controller: LDAP server signing requirements`
   * **Setting**: `Require signing`
5. Link the GPO to the Domain Controllers OU.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-LDAPSigning.ps1](implementation_scripts/Configure-LDAPSigning.ps1)

```powershell
# Configure-LDAPSigning.ps1
# Description: Configures the LDAP server signing requirement to Require Signing.

Write-Host "Applying hardening requirement: Enforce LDAP Server Signing..." -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

Set-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -Value 2 -Type DWord
Write-Host "LDAP Server Integrity set to 2 (Require Signing)." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-LDAPSigningStatus.ps1](audit_scripts/Get-LDAPSigningStatus.ps1)

```powershell
# Get-LDAPSigningStatus.ps1
# Description: Audits the LDAP server signing configuration in the registry.

Write-Host "--- Auditing LDAP Server Signing ---" -ForegroundColor Cyan

$regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
$ntdsReg = Get-ItemProperty -Path $regPath -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue

if ($ntdsReg) {
    $integrityVal = $ntdsReg.LDAPServerIntegrity
    if ($integrityVal -eq 2) {
        Write-Host "[+] LDAP Server Signing is secure. LDAPServerIntegrity is set to $($integrityVal) (Require Signing)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: LDAPServerIntegrity is set to $($integrityVal) (Required: 2)." -ForegroundColor Red
    }
} else {
    Write-Host "[!] VULNERABLE: LDAPServerIntegrity registry value is missing. The system uses default negotiation (allows unsigned connections)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R19 (LDAP Signing)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.3.3.1 (Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing')
* **Microsoft Security Guidance**: Active Directory LDAP signing requirements
