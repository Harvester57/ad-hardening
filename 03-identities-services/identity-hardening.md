# Module 3: Identities and Services Hardening

This module focuses on securing Active Directory user accounts, service accounts, and authentication protocols. Compromising user identities or exploiting service configurations are the primary avenues for domain escalation. 

---

## 1. User Accounts and Password Policies

Standard domain-wide password policies are often too weak for administrative accounts. Active Directory allows defining granular policies.

### Fine-Grained Password Policies (FGPP)
* **Requirement**: Implement FGPP (Password Settings Objects - PSOs) for all administrative accounts (Tier 0 and Tier 1). 
* **Hardening Thresholds**:
  * **Standard Users**: Minimum 14 characters, complexity enabled, lockout after 10 failed attempts.
  * **Administrative Accounts (Tier 0 / Tier 1)**: Minimum 20 characters, complexity enabled, lockout after 5 failed attempts.

### Restricting Privileged Group Membership
* Memberships in `Domain Admins`, `Enterprise Admins`, and `Schema Admins` must be restricted to the absolute minimum (often empty, utilizing secondary admin accounts only when changes are active).
* The default RID 500 `Administrator` account must be disabled or renamed, and its password randomized.

---

## 2. Local Administrator Password Solution (LAPS)

In an air-gapped environment, local administrator passwords on member servers and workstations must not be identical (to prevent lateral movement if one machine is compromised).

* **Requirement**: Implement **Windows LAPS** (built into modern Windows 10/Server 2016 patch levels) or **Classic Microsoft LAPS**.
* **Configuration**:
  * Store local admin passwords securely in Active Directory (encrypted via AD permissions).
  * Automatically rotate passwords every 30 days (minimum length of 20 characters with complexity).
  * Limit read permissions on the `ms-Mcs-AdmPwd` (classic) or `msLAPS-Password` (modern) attribute to authorized Tier 0/1 administrators only.

---

## 3. Service Account Hardening (gMSA / sMSA)

Traditional service accounts use static passwords that rarely change, making them highly vulnerable to Kerberoasting.

* **Requirement**: Deprecate traditional domain user accounts for running services. Replace them with **Group Managed Service Accounts (gMSAs)**.
* **Benefits**:
  * Windows automatically manages the password (120-character complex password, rotated every 30 days).
  * Eliminates the risk of Kerberoasting (as service ticket requests cannot be brute-forced offline).
  * Prevents interactive logons (gMSAs cannot log on interactively).

---

## 4. Kerberos Hardening & Delegation

Kerberos is the primary authentication protocol in Active Directory. Secure configuration of encryption types and delegation settings is essential.

### Disabling Weak Encryption Types
* **Risk**: If RC4 or DES encryption is allowed, attackers can intercept Kerberos tickets and perform offline brute-force attacks (Kerberoasting) far more easily due to weak cryptographic keys.
* **Requirement**: Force AES128 and AES256 encryption. Disable RC4 and DES.

### Restricting Kerberos Delegation (ANSSI R15, R16)
* **Unconstrained Delegation**: This allows a service to impersonate a user to *any* downstream service. If an attacker compromises a server with unconstrained delegation, they can capture the TGT of any user (including Domain Admins) who authenticates to that server.
  * **Requirement**: **Ban Unconstrained Delegation entirely.**
* **Constrained Delegation (S4U2Proxy)**: Restricts delegation to specific target services.
* **Resource-Based Constrained Delegation (RBCD)**: Configures delegation on the target resource itself, offering superior security boundaries and easier management.

---

## PowerShell Implementation Guide

### 1. Auditing Identity & Kerberos Vulnerabilities (Audit)

Run this script from an administrative workstation with Active Directory PowerShell module installed to audit password settings, gMSAs, Kerberos encryption, and delegation issues.

```powershell
# Audit-ADIdentities.ps1
# Audits Active Directory users, service accounts, and delegation settings.

Import-Module ActiveDirectory

Write-Host "--- Auditing Active Directory Identities ---" -ForegroundColor Cyan

# 1. Audit Fine-Grained Password Policies (FGPP)
$psoList = Get-ADFineGrainedPasswordPolicy -Filter *
Write-Host "`n[+] Checking Fine-Grained Password Policies (PSOs) Found: $($psoList.Count)" -ForegroundColor Yellow
foreach ($pso in $psoList) {
    Write-Host "    - PSO Name: $($pso.Name) | Precedence: $($pso.Precedence) | MinLength: $($pso.MinPasswordLength)" -ForegroundColor White
}

# 2. Audit Accounts with Unconstrained Delegation
Write-Host "`n[+] Checking for Accounts with Unconstrained Delegation (Vulnerable)..." -ForegroundColor Yellow
$unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true}
$unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true}

$totalUnconstrained = $unconstrainedComputers.Count + $unconstrainedUsers.Count
if ($totalUnconstrained -eq 0) {
    Write-Host "    No accounts found with Unconstrained Delegation (Safe)." -ForegroundColor Green
} else {
    foreach ($comp in $unconstrainedComputers) {
        Write-Host "    - Computer (Vulnerable): $($comp.SamAccountName) (DN: $($comp.DistinguishedName))" -ForegroundColor Red
    }
    foreach ($user in $unconstrainedUsers) {
        Write-Host "    - User (Vulnerable): $($user.SamAccountName) (DN: $($user.DistinguishedName))" -ForegroundColor Red
    }
}

# 3. Audit Accounts Supporting Weak Encryption (RC4 or DES)
Write-Host "`n[+] Checking for accounts restricted to DES encryption..." -ForegroundColor Yellow
$desAccounts = Get-ADUser -Filter {UseDESKeyOnly -eq $true}
if ($desAccounts.Count -eq 0) {
    Write-Host "    No accounts restricted to DES (Safe)." -ForegroundColor Green
} else {
    foreach ($acct in $desAccounts) {
        Write-Host "    - Account: $($acct.SamAccountName)" -ForegroundColor Red
    }
}

# 4. Audit Group Managed Service Accounts (gMSAs)
$gMSAs = Get-ADServiceAccount -Filter *
Write-Host "`n[+] Registered Group Managed Service Accounts: $($gMSAs.Count)" -ForegroundColor Yellow
foreach ($sa in $gMSAs) {
    Write-Host "    - gMSA: $($sa.SamAccountName) | Enabled: $($sa.Enabled)" -ForegroundColor White
}
```

### 2. Remediating Identity and Service Configurations (Remediation)

Execute the following PowerShell commands to enforce AES encryption on accounts, create a Fine-Grained Password Policy (PSO), and set up a new gMSA.

```powershell
# Set-ADIdentityRemediation.ps1
# Configures secure defaults for AD identities.

Import-Module ActiveDirectory

Write-Host "--- Applying Identity Hardening Remediation ---" -ForegroundColor Cyan

# 1. Enforce AES-Only Encryption on all User Accounts (msDS-SupportedEncryptionTypes = 24)
# Value 24 represents AES128 (8) + AES256 (16) = 24
Write-Host "[+] Enforcing AES128/AES256 encryption on domain user accounts..." -ForegroundColor Gray
$TargetUsers = Get-ADUser -Filter {Enabled -eq $true}
foreach ($User in $TargetUsers) {
    # Set msDS-SupportedEncryptionTypes to 24 (AES Only)
    Set-ADUser -Identity $User -Replace @{"msDS-SupportedEncryptionTypes" = 24}
}
Write-Host "    AES encryption enforced on all active users." -ForegroundColor Green

# 2. Create a Fine-Grained Password Policy for Admins
$AdminPSOName = "Tier0-Admin-PSO"
Write-Host "[+] Creating Fine-Grained Password Policy: $AdminPSOName..." -ForegroundColor Gray
$ExistingPSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$AdminPSOName'"

if (-not $ExistingPSO) {
    New-ADFineGrainedPasswordPolicy -Name $AdminPSOName `
        -Precedence 10 `
        -ComplexityEnabled $true `
        -MinPasswordLength 20 `
        -PasswordHistoryCount 24 `
        -ReversibleEncryptionEnabled $false `
        -LockoutDuration "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 `
        -MinPasswordAge "1.00:00:00" `
        -MaxPasswordAge "60.00:00:00"
    Write-Host "    PSO '$AdminPSOName' created." -ForegroundColor Green
} else {
    Write-Host "    PSO '$AdminPSOName' already exists." -ForegroundColor Yellow
}

# 3. Create a Group Managed Service Account (gMSA)
# Note: In an air-gapped domain, a KDS Root Key must be created first.
Write-Host "[+] Ensuring KDS Root Key exists for gMSA generation..." -ForegroundColor Gray
try {
    # In production, Active Directory requires up to 10 hours for the key to propagate.
    # We add -EffectiveImmediately for lab/instant configurations.
    Add-KdsRootKey -EffectiveImmediately -ErrorAction SilentlyContinue
    Write-Host "    KDS Root Key verified/created." -ForegroundColor Green
} catch {
    Write-Warning "Could not create KDS Root Key. It may already exist or you lack schema rights."
}

$gMSAName = "gmsa-sqlservice"
Write-Host "[+] Registering gMSA '$gMSAName'..." -ForegroundColor Gray
$existingMSA = Get-ADServiceAccount -Filter "Name -eq '$gMSAName'"
if (-not $existingMSA) {
    # Create the service account and permit Domain Controllers/Servers to retrieve password
    New-ADServiceAccount -Name $gMSAName `
        -DNSHostName "$gMSAName.domain.local" `
        -ManagedPasswordIntervalInDays 30 `
        -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers", "Schema Admins"
    Write-Host "    gMSA '$gMSAName' created successfully." -ForegroundColor Green
} else {
    Write-Host "    gMSA '$gMSAName' already exists." -ForegroundColor Yellow
}
```
