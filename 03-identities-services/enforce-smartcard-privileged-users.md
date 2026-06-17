# [REQ-ID-019] Enforce Smart Card Authentication for Privileged Users

## Target Scope
* **Applicable Systems**: Active Directory Domain Services (AD DS) user accounts, Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **AD Configuration / PowerShell Attribute**:
  * **AD User Attribute**: `userAccountControl` flag `UF_SMARTCARD_REQUIRED` (value `0x40000` / `262144`)
  * **PowerShell AD Property**: `SmartcardRequired` set to `$true`

---

## Rationale
Enforcing smart card authentication on privileged accounts significantly mitigates the risk of credential theft, lateral movement, and offline password cracking:

1. **Hash and Password Extraction Prevention**: By checking "Smart card is required for interactive logon" on an Active Directory user account, AD automatically rotates the account's password to a cryptographically strong, random 120-character string that is unknown to the user. This effectively invalidates the traditional NTHash and LMHash authentication methods, preventing attackers from performing password-spraying or brute-force attacks against administrative logins.
2. **Replay and Relay Mitigation**: Password-based authentication relies on credentials that can be captured, logged, or relay-attacked. Using smart cards (or physical tokens like YubiKeys) shifts authentication to Kerberos PKINIT (Public Key Cryptography for Initial Authentication in Kerberos). This protocol relies on private keys stored in the card's secure hardware element, ensuring credentials cannot be copied or replayed.
3. **Physical Presence Factor**: Combining a hardware token (something you have) and a PIN (something you know) establishes true multi-factor authentication (MFA) for administrative activities, preventing unauthorized access by remote network attackers who have compromised a password.

---

## Legacy Impact & Compatibility
* **Password Logons Disabled**: Privileged administrators will no longer be able to log on using standard username and password combinations. They must have physical/virtual smart cards and card readers actively connected to the workstation.
* **PKI Dependency**: A fully operational Enterprise PKI (Active Directory Certificate Services - AD CS) must be deployed. Domain Controllers must be issued valid certificates supporting KDC authentication. If the PKI is unavailable or certificates expire, users will be unable to log on.
* **Service Account & Script Breaks**: Administrators must not use personal administrative accounts to run automated scripts or services that rely on static password authentication. Such configurations will break and must be migrated to Group Managed Service Accounts (gMSAs) or managed via scheduled tasks utilizing certificate-based operations.
* **Break-Glass (Emergency) Accounts**: Break-glass accounts must be excluded from this policy if they do not have active smart card tokens, or they must be assigned dedicated hardware smart cards stored in physical security safes under dual-custody.

---

## Implementation Steps

### Option A: Active Directory Administrative Tools (Preferred)

To configure smart card requirement for individual privileged users or OUs:
1. Open **Active Directory Users and Computers** (`dsa.msc`) on a domain controller or administrative host.
2. Navigate to the Organizational Unit (OU) containing your administrative users.
3. Right-click the target administrator account and select **Properties**.
4. Click on the **Account** tab.
5. In the **Account options** window, scroll down and check the box: **Smart card is required for interactive logon**.
6. Click **Apply** and then **OK**.

Alternatively, you can select multiple users at once, right-click, select **Properties**, click the **Account** tab, select the check box next to **Smart card is required for interactive logon** under **Account options**, and click **OK** to apply the policy in batch.

---

### Option B: PowerShell Script (Remediation / Automation)

Use these scripts locally on a Domain Controller or a management machine with Active Directory administrative tools installed to enforce or audit the smart card requirement.

[Download Script: Configure-PrivilegedSmartCard.ps1](implementation_scripts/Configure-PrivilegedSmartCard.ps1)

```powershell
# Configure-PrivilegedSmartCard.ps1
# Description: Enforces the 'Smart card is required for interactive logon' flag on a specified user group.
# Target Engine: Windows PowerShell 5.1

Write-Host "Applying smart card logon requirement to administrative accounts..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell module is not available. Please run this script on a system with AD DS RSAT tools."
    exit 1
}

Import-Module ActiveDirectory

$GroupName = "Tier0_Administrators"
$Group = Get-ADGroup -Filter "Name -eq '$GroupName'"
if (-not $Group) {
    Write-Host "Group $GroupName not found. Defaulting to Domain Admins..." -ForegroundColor Yellow
    $GroupName = "Domain Admins"
}

$Members = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }

if (-not $Members) {
    Write-Host "No users found in group $GroupName." -ForegroundColor Yellow
    exit 0
}

foreach ($Member in $Members) {
    $User = Get-ADUser -Identity $Member.distinguishedName -Properties SmartcardRequired
    if (-not $User.SmartcardRequired) {
        Write-Host "Enforcing smart card requirement for user: $($User.SamAccountName)" -ForegroundColor Cyan
        Set-ADUser -Identity $User.distinguishedName -SmartcardRequired $true
    } else {
        Write-Host "User $($User.SamAccountName) already requires smart card." -ForegroundColor Green
    }
}

Write-Host "Smart card requirement configuration complete." -ForegroundColor Green
```

*To audit the smart card requirement on privileged users:*

[Download Script: Test-PrivilegedSmartCard.ps1](audit_scripts/Test-PrivilegedSmartCard.ps1)

```powershell
# Test-PrivilegedSmartCard.ps1
# Description: Audits if all members of the specified administrative group require smart card for logon.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Privileged User Smart Card Requirements ---" -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Warning "ActiveDirectory PowerShell module is not available. Please install RSAT AD DS tools."
    exit 0
}

Import-Module ActiveDirectory

$GroupName = "Tier0_Administrators"
$Group = Get-ADGroup -Filter "Name -eq '$GroupName'"
if (-not $Group) {
    Write-Host "Group $GroupName not found. Defaulting audit to Domain Admins..." -ForegroundColor Yellow
    $GroupName = "Domain Admins"
}

$Vulnerable = $false
$Members = Get-ADGroupMember -Identity $GroupName -Recursive | Where-Object { $_.objectClass -eq "user" }

if (-not $Members) {
    Write-Host "No users found in group $GroupName to audit." -ForegroundColor Yellow
} else {
    foreach ($Member in $Members) {
        $User = Get-ADUser -Identity $Member.distinguishedName -Properties SmartcardRequired
        if (-not $User.SmartcardRequired) {
            Write-Host "    - User: $($User.SamAccountName) | Actual: Password Allowed (Expected: Smart Card Required)" -ForegroundColor Red
            $Vulnerable = $true
        } else {
            Write-Host "    - User: $($User.SamAccountName) | Actual: Smart Card Required (Expected: Smart Card Required)" -ForegroundColor Green
        }
    }
}

if ($Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations on administrator identification, multi-factor authentication, and password hash isolation.
* **CIS Microsoft Windows Server Benchmark**: Section 1.2 (Account policies) and Section 2.3.9.5 (Interactive logon: Smart card removal behavior).
* **Microsoft Security Guidance**: Protecting high-privilege credentials in Active Directory.
