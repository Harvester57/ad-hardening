# Hardening Requirement: Configure and Populate Protected Users Group

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Built-in Group: `CN=Protected Users,CN=Users,DC=[Domain]`

---

## Rationale
Standard administrative accounts are highly vulnerable to credential harvesting attacks. If a Domain Admin or other high-privilege account authenticates to a compromised workstation or member server, their credentials (passwords, Kerberos TGTs, NTLM hashes) remain cached in the Local Security Authority Subsystem Service (LSASS) memory. Attackers can extract these credentials using tools like Mimikatz to escalate privileges or move laterally.

The **Protected Users** security group (introduced in Windows Server 2012 R2) enforces non-configurable, highly secure authentication restrictions on its members. These protections include:
1. **No NTLM caching**: NTLM password hashes are not cached locally, and members cannot authenticate via NTLM.
2. **Short Kerberos TGT lifetimes**: Ticket Granting Tickets (TGTs) are limited to 4 hours and cannot be renewed beyond that.
3. **No weak encryption**: Members cannot use DES or RC4 encryption for Kerberos pre-authentication.
4. **No CredSSP or WDigest caching**: Cleartext credentials are never cached by the local system.
5. **No delegation**: Kerberos delegation (constrained or unconstrained) is blocked for accounts in this group.

Placing Tier 0 and Tier 1 administrative accounts into the Protected Users group significantly reduces the threat of credential harvesting.

---

## Legacy Impact & Compatibility
* **NTLM Authentication Blocked**: Any application or administrative process that authenticates using a Protected User account via NTLM (instead of Kerberos) will fail. Ensure DNS resolution and Kerberos pathways are fully functional.
* **Short Session Lifetimes**: Administrative sessions will require re-authentication after 4 hours due to the non-configurable TGT limit.
* **No Delegation**: If an administrator needs to manage services that rely on delegation, secondary non-delegated accounts must be used, or delegation must be re-architected.

---

## Implementation Steps

### Option A: Active Directory Users and Computers Console Configuration (Preferred)

1. Open **Active Directory Users and Computers** (`dsa.msc`).
2. Navigate to the **Users** container (or where the built-in groups are located).
3. Double-click the **Protected Users** security group.
4. Click the **Members** tab.
5. Click **Add**.
6. Type the names of the Tier 0 and Tier 1 administrative accounts (e.g., `admin-t0-user`) and click **OK**.
7. Click **Apply** and then **OK**.
8. Ask the administrators to sign out and sign back in for the security group memberships to take effect.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script to add administrative accounts to the Protected Users security group using PowerShell.

[Download Script: Set-ProtectedUsers.ps1](implementation_scripts/Set-ProtectedUsers.ps1)

```powershell
# Set-ProtectedUsers.ps1
# Description: Adds privileged accounts to the Protected Users group.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Populate Protected Users Group..." -ForegroundColor Cyan

$GroupName = "Protected Users"
$TargetAdmins = @("admin-t0-user", "admin-t1-user")

foreach ($Admin in $TargetAdmins) {
    $User = Get-ADUser -Filter "SamAccountName -eq '$Admin'"
    
    if ($User) {
        # Check if already a member
        $isMember = Get-ADGroupMember -Identity $GroupName | Where-Object { $_.SamAccountName -eq $Admin }
        
        if (-not $isMember) {
            Add-ADGroupMember -Identity $GroupName -Members $User
            Write-Host "[+] Added $Admin to Protected Users group." -ForegroundColor Green
        } else {
            Write-Host "[-] User $Admin is already a member of Protected Users group." -ForegroundColor Yellow
        }
    } else {
        Write-Warning "User '$Admin' not found in Active Directory."
    }
}
```

*To audit the members of the Protected Users group:*
[Download Script: Get-ProtectedUsersStatus.ps1](audit_scripts/Get-ProtectedUsersStatus.ps1)

```powershell
# Get-ProtectedUsersStatus.ps1
# Description: Lists all members of the Protected Users security group.

Import-Module ActiveDirectory

Write-Host "--- Auditing Protected Users Group Members ---" -ForegroundColor Cyan

$GroupName = "Protected Users"
$Members = Get-ADGroupMember -Identity $GroupName -ErrorAction SilentlyContinue

if ($Members) {
    Write-Host "[+] Members of the Protected Users group:" -ForegroundColor Green
    foreach ($Member in $Members) {
        Write-Host "    - $($Member.SamAccountName) (Type: $($Member.objectClass))" -ForegroundColor White
    }
} else {
    Write-Host "[!] VULNERABLE: No members found in the Protected Users group. Administrative accounts may be unprotected." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R14 (Use of Protected Users group)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section on Account Lockout and Protected Groups
* **Microsoft Security Guidance**: Protected Users Security Group Technical Reference
