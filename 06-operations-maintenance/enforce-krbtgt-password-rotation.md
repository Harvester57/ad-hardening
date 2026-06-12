# Hardening Requirement: Enforce KRBTGT Password Rotation

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Object Management (krbtgt account object in the Users container: `CN=krbtgt,CN=Users,DC=[Domain]`)

{% hint style="warning" %}
The `krbtgt` account password must be rotated periodically to limit the lifespan of potentially compromised Ticket Granting Tickets (TGTs).
* **Standard Frequency**: Reset the password at least every 180 days (semi-annually) in accordance with the DoD STIG requirement.
* **High-Security Frequency**: High-security baselines (such as the ANSSI Active Directory hardening guide) recommend rotating the password every 40 days in high-security environments.
* **Ad-Hoc Rotation**: Perform an immediate two-step rotation in the event of a suspected Active Directory compromise, or following the departure of key administrative staff with Tier 0 access.
{% endhint %}

---

## Rationale
The `krbtgt` account is a built-in local service account that serves as the Key Distribution Center (KDC) service account in Active Directory. The password hash of the `krbtgt` account is used to sign and encrypt all Kerberos Ticket Granting Tickets (TGTs) issued within the domain. 

If an attacker compromises the Active Directory database (e.g., via NTDS.dit extraction) or obtains Domain Admin privileges, they can dump the `krbtgt` password hash and use it to craft forged Kerberos TGTs (a Golden Ticket attack). Golden Tickets allow attackers to authenticate as any user (including Domain Admins) to any service in the forest, bypassing password changes and maintaining persistent, virtually invisible administrative access.

To mitigate the risk of Golden Ticket persistence, the `krbtgt` password must be rotated periodically. Active Directory stores the current password (history index 0) and the immediately previous password (history index 1) for the `krbtgt` account. This design allows existing tickets to remain valid until they expire or are renewed, avoiding service disruptions. 

Therefore, a complete rotation requires resetting the password twice. The resets must be separated by a sufficient time window to allow the first reset to replicate across all domain controllers and for existing Kerberos ticket lifetimes (default of 10 hours) to expire.

---

## Legacy Impact & Compatibility
* **Authentication Outages**: Resetting the `krbtgt` password twice in rapid succession (without waiting for replication and Kerberos ticket lifetimes to elapse) will invalidate all active TGTs immediately. This will cause widespread authentication failures across the domain for all users, services, and trust relationships.
* **Operational Wait Time**: A minimum of 10 hours (24 hours is recommended in production) must be observed between the first and second reset to allow replication to converge and existing tickets to naturally expire or renew.
* **Trust Relationships**: Forest trusts and external trusts will not be impacted, but the ticket lifetime window must be strictly respected to prevent inter-forest Kerberos authentication issues.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Note: This control cannot be implemented or managed via standard Group Policy Objects (GPO). The KRBTGT password rotation is an operational database task performed directly on the Active Directory objects. 

To execute the manual graphical procedure using Active Directory Users and Computers (ADUC):

1. Log on to a Domain Controller or management workstation with Domain Admin credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. Click the **View** menu at the top and ensure **Advanced Features** is enabled.
4. Navigate to the **Users** container (or the custom Organizational Unit where the `krbtgt` account resides).
5. Locate the **krbtgt** account.
6. Right-click the **krbtgt** account and select **Reset Password**.
7. Enter a strong, randomly generated, complex password (minimum 128 characters) and confirm it. Click **OK**.
8. Verify that Active Directory replication is healthy across all Domain Controllers.
9. Wait at least 10 to 24 hours (allowing the default 10-hour Kerberos ticket lifetime to elapse).
10. Repeat steps 4-7 to perform the second password reset, retiring the compromised key from the password history.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following scripts to audit the age of the `krbtgt` password and programmatically perform a reset.

[Download Script: Reset-KrbtgtPassword.ps1](implementation_scripts/Reset-KrbtgtPassword.ps1)

```powershell
# Reset-KrbtgtPassword.ps1
# Description: Resets the password of the krbtgt account with a strong, random password.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: KRBTGT Password Rotation..." -ForegroundColor Cyan

# 1. Retrieve the krbtgt account
$Krbtgt = Get-ADUser -Filter "Name -eq 'krbtgt'" -Properties PasswordLastSet, Enabled
if (-not $Krbtgt) {
    Write-Error "KRBTGT account not found in the Active Directory domain."
    return
}

Write-Host "Current KRBTGT Password Last Set: $($Krbtgt.PasswordLastSet)" -ForegroundColor White

# 2. Generate a strong random password (128 characters)
$Length = 128
$Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
$RandomPassword = -join (1..$Length | ForEach-Object { $Chars[(Get-Random -Maximum $Chars.Length)] })

$SecurePassword = New-Object System.Security.SecureString
foreach ($Char in $RandomPassword.ToCharArray()) {
    $SecurePassword.AppendChar($Char)
}

# 3. Apply the password change
try {
    Set-ADAccountPassword -Identity $Krbtgt -NewPassword $SecurePassword -Reset -ErrorAction Stop
    Write-Host "[OK] KRBTGT password has been successfully reset." -ForegroundColor Green
    Write-Host "[IMPORTANT] This is a single password reset." -ForegroundColor Yellow
    Write-Host "[IMPORTANT] To fully invalidate old Kerberos tickets (e.g., to recover from Golden Ticket compromise)," -ForegroundColor Yellow
    Write-Host "            you MUST perform a second reset AFTER all domain controllers have replicated the first reset" -ForegroundColor Yellow
    Write-Host "            and the maximum Kerberos ticket lifetime (default 10 hours) has elapsed." -ForegroundColor Yellow
} catch {
    Write-Error "Failed to reset KRBTGT password: $($_.Exception.Message)"
}
```

*To audit the password last set age of the KRBTGT account:*
[Download Script: Get-KrbtgtRotationStatus.ps1](audit_scripts/Get-KrbtgtRotationStatus.ps1)

```powershell
# Get-KrbtgtRotationStatus.ps1
# Description: Audits the password age of the krbtgt account.

Import-Module ActiveDirectory

Write-Host "--- Auditing KRBTGT Password Rotation Status ---" -ForegroundColor Cyan

$Krbtgt = Get-ADUser -Filter "Name -eq 'krbtgt'" -Properties PasswordLastSet, PasswordExpired, Enabled

if ($Krbtgt) {
    $PasswordLastSet = $Krbtgt.PasswordLastSet
    if ($null -ne $PasswordLastSet) {
        $AgeDays = (New-TimeSpan -Start $PasswordLastSet -End (Get-Date)).Days
        $MaxAgeDays = 180 # STIG requirement threshold
        
        Write-Host "    - Account Name: $($Krbtgt.Name)" -ForegroundColor White
        Write-Host "    - Enabled: $($Krbtgt.Enabled)" -ForegroundColor White
        Write-Host "    - Password Last Set: $PasswordLastSet ($AgeDays days ago)" -ForegroundColor White
        
        if ($AgeDays -gt $MaxAgeDays) {
            Write-Host "    - Status: WARNING - KRBTGT password has not been rotated in $AgeDays days (Threshold: $MaxAgeDays days)." -ForegroundColor Red
        } else {
            Write-Host "    - Status: OK - KRBTGT password was rotated recently ($AgeDays days ago)." -ForegroundColor Green
        }
    } else {
        Write-Host "    - Status: WARNING - PasswordLastSet is not set for the krbtgt account." -ForegroundColor Red
    }
} else {
    Write-Error "KRBTGT account not found in the Active Directory domain."
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on secrets renewal (Renouvellement des secrets de l'Active Directory)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark (General guidance on periodic Kerberos key rotation)
* **DoD STIG**: Windows Server Domain Controller STIG (V-205877, V-225006, V-254427) - The krbtgt account password must be reset at least every 180 days.
* **Microsoft Security Guidance**: Securing the KRBTGT Account / AD Forest Recovery Guide
