# Hardening Requirement: Enforce Kerberos Pre-Authentication

## Target Scope
* **Applicable Systems**: Domain Controllers (Active Directory User Accounts)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory User Account Control Attribute (flag `DONOTREQ_PREAUTH` / 0x400000)

---

## Rationale
Kerberos Pre-Authentication serves as the primary line of defense against AS-REP Roasting. AS-REP Roasting is a credential theft technique where attackers target accounts that do not require Kerberos pre-authentication.

Without pre-authentication:
1. **Unauthenticated Requesting**: The Key Distribution Center (KDC) will issue a Ticket Granting Ticket (TGT) encrypted with the user's secret key (derived from their password) to any client that requests it, without requiring the client to authenticate or prove identity first.
2. **Offline Password Cracking**: An attacker can request a TGT for a target user, intercept the KDC's response (AS-REP payload), and take the encrypted data offline. They can then perform brute-force or dictionary attacks to crack the password hash without triggering account lockout policies or generating logon failure logs.

By enforcing pre-authentication, the KDC requires the client to encrypt a timestamp using their password hash before issuing the TGT. This proves the client possesses the password, preventing attackers from retrieving the encrypted AS-REP token for offline cracking.

---

## Legacy Impact & Compatibility
* **Authentication Failure**: Accounts linked to very old or poorly designed application integrations, legacy mainframes, or third-party appliances that do not support Kerberos pre-authentication will fail to authenticate. These service integrations must be upgraded to support standard Kerberos pre-authentication or transitioned to secure modern service account models (like gMSAs).
* **Initial Audit**: Administrators must audit the environment to locate and analyze why any accounts have pre-authentication disabled prior to enforcing the setting.

---

## Implementation Steps

### Option A: Active Directory Users and Computers (Preferred)

1. Log on to a Domain Controller or administrative workstation with **Account Operators** or **Domain Admins** credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. Locate the target user account, right-click it, and select **Properties**.
4. Navigate to the **Account** tab.
5. In the **Account options** list, scroll down and ensure that the checkbox for **Do not require Kerberos preauthentication** is **unchecked** (disabled).
6. Click **Apply** and **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts to audit and remediate accounts in the forest.

#### 1. Local AD Audit (Audit-KerberosPreAuth.ps1)

[Download Script: Audit-KerberosPreAuth.ps1](audit_scripts/Audit-KerberosPreAuth.ps1)

```powershell
# Audit-KerberosPreAuth.ps1
# Description: Audits active user accounts to find any with pre-authentication disabled.

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberos Pre-Authentication Status ---" -ForegroundColor Cyan

try {
    # Search for enabled accounts with DONOTREQ_PREAUTH (0x400000) active
    $VulnerableAccounts = Get-ADUser -Filter "DoesNotRequirePreAuth -eq '$true'" -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.Enabled -eq $true }
    
    if ($VulnerableAccounts) {
        Write-Host "`nVULNERABLE: Found $($VulnerableAccounts.Count) enabled user account(s) with Kerberos Pre-Authentication disabled:" -ForegroundColor Red
        foreach ($acc in $VulnerableAccounts) {
            Write-Host "    - User: $($acc.SamAccountName) | DN: $($acc.DistinguishedName)" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. All enabled user accounts require Kerberos Pre-Authentication." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit accounts. Error: $($_.Exception.Message)" -ForegroundColor Red
}
```

#### 2. Local AD Remediation (Set-KerberosPreAuth.ps1)

[Download Script: Set-KerberosPreAuth.ps1](implementation_scripts/Set-KerberosPreAuth.ps1)

```powershell
# Set-KerberosPreAuth.ps1
# Description: Enforces Kerberos Pre-Authentication on all active user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce Kerberos Pre-Authentication..." -ForegroundColor Cyan

try {
    $VulnerableAccounts = Get-ADUser -Filter "DoesNotRequirePreAuth -eq '$true'" -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.Enabled -eq $true }
    
    if ($VulnerableAccounts) {
        Write-Host "[+] Found $($VulnerableAccounts.Count) accounts requiring remediation." -ForegroundColor Yellow
        foreach ($acc in $VulnerableAccounts) {
            Set-ADAccountControl -Identity $acc.SamAccountName -DoesNotRequirePreAuth $false -ErrorAction Stop
            Write-Host "    Remediated: $($acc.SamAccountName)" -ForegroundColor Green
        }
        Write-Host "[+] All target accounts successfully remediated." -ForegroundColor Green
    } else {
        Write-Host "[+] No vulnerable accounts found. Pre-Authentication is already enforced." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enforce Kerberos Pre-Authentication. Error: $($_.Exception.Message)"
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Technical recommendations regarding Kerberos protocol security.
* **CIS Microsoft Windows Server Benchmark**: User Account Control security baseline configuration.
* **MITRE ATT&CK**: Technique T1558.004 (AS-REP Roasting).
