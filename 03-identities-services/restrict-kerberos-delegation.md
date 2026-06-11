# Hardening Requirement: Restrict Kerberos Delegation

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Object Attributes (`userAccountControl` flags: `ADS_UF_TRUSTED_FOR_DELEGATION` = `0x80000`)

---

## Rationale
Kerberos delegation allows a service to impersonate a user to access downstream resources on behalf of that user. In **Unconstrained Delegation**, when a user authenticates to a service, the user's Ticket Granting Ticket (TGT) is sent to the service server and stored in LSASS memory. If an attacker compromises that service server, they can extract the cached TGTs of all users who have authenticated to it (including Domain Admins) and impersonate them across the entire domain.

To prevent this critical privilege escalation path, **Unconstrained Delegation must be banned entirely**. Any required delegation should be restricted to **Constrained Delegation** or **Resource-Based Constrained Delegation (RBCD)**, which specify exactly which target services can receive delegated credentials.

---

## Legacy Impact & Compatibility
* **Application Functionality**: Disabling unconstrained delegation on legacy servers might break multi-tier applications (e.g., Web Frontend -> SQL Backend) if they have not been configured for constrained delegation or RBCD.
* **Transition Plan**: Before disabling unconstrained delegation, identify the specific Service Principal Names (SPNs) and destination services required, and configure Constrained Delegation (S4U2Proxy) to allow only those pathways.

---

## Implementation Steps

### Option A: Active Directory Users and Computers Console Configuration (Preferred)

1. Open **Active Directory Users and Computers** (`dsa.msc`).
2. Locate the computer or user account that has unconstrained delegation enabled.
3. Right-click the object and select **Properties**.
4. Go to the **Delegation** tab.
5. Select **Do not trust this computer for delegation** to disable unconstrained delegation.
6. Alternatively, to configure Constrained Delegation:
   * Select **Trust this computer for delegation to specified services only**.
   * Select **Use Kerberos only** or **Use any authentication protocol** (S4U2Self/Protocol Transition).
   * Click **Add** to specify the target services.
7. Click **Apply** and then **OK**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following PowerShell script to audit and disable unconstrained delegation on all computers and users.

```powershell
# Set-RestrictDelegation.ps1
# Description: Disables unconstrained delegation on computer and user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Restrict Kerberos Delegation..." -ForegroundColor Cyan

# Find all computer accounts with Unconstrained Delegation
$unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true}
foreach ($comp in $unconstrainedComputers) {
    Write-Host "[*] Disabling Unconstrained Delegation on Computer: $($comp.SamAccountName)" -ForegroundColor Gray
    Set-ADComputer -Identity $comp -TrustedForDelegation $false
}

# Find all user accounts with Unconstrained Delegation
$unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true}
foreach ($user in $unconstrainedUsers) {
    Write-Host "[*] Disabling Unconstrained Delegation on User: $($user.SamAccountName)" -ForegroundColor Gray
    Set-ADUser -Identity $user -TrustedForDelegation $false
}

Write-Host "Unconstrained delegation has been disabled on all identified accounts." -ForegroundColor Green
```

*To audit delegation settings in the domain:*
```powershell
# Get-KerberosDelegationStatus.ps1
# Description: Audits accounts with unconstrained delegation in the Active Directory domain.

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberos Delegation Settings ---" -ForegroundColor Cyan

$unconstrainedComputers = Get-ADComputer -Filter {TrustedForDelegation -eq $true}
$unconstrainedUsers = Get-ADUser -Filter {TrustedForDelegation -eq $true}

$totalUnconstrained = $unconstrainedComputers.Count + $unconstrainedUsers.Count

if ($totalUnconstrained -eq 0) {
    Write-Host "[+] Secure: No accounts found with Unconstrained Delegation." -ForegroundColor Green
} else {
    foreach ($comp in $unconstrainedComputers) {
        Write-Host "[!] VULNERABLE: Computer with Unconstrained Delegation: $($comp.SamAccountName)" -ForegroundColor Red
    }
    foreach ($user in $unconstrainedUsers) {
        Write-Host "[!] VULNERABLE: User with Unconstrained Delegation: $($user.SamAccountName)" -ForegroundColor Red
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R15 (Unconstrained Delegation ban) and R16 (Restricting Constrained Delegation)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section on Kerberos Delegation
* **Microsoft Security Guidance**: Kerberos Delegation Overview and Security Risks
