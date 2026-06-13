# [REQ-ID-012] Configure Active Directory Authentication Silos and Policies

## Target Scope
* **Applicable Systems**: Domain Controllers, Tier 0 Administration Workstations (PAWs), Tier 0 Administrator Accounts
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: 
  * **Active Directory Path**: `CN=AuthN Silos,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=[Domain]`
  * **KDC GPO Policy**: `Computer Configuration\Policies\Administrative Templates\System\KDC\Support for claims, compound authentication and Kerberos armoring` -> Enabled (Supported)

---

## Rationale
Standard Active Directory group memberships define access permissions but do not prevent highly privileged accounts from authenticating to lower-trust systems. If an administrator accidentally logs on to a compromised Tier 1/2 machine, their credentials can be stolen.

Authentication Silos and Policies provide cryptographic containment:
1. **Enforces Logon Boundaries**: An Authentication Silo bounds a set of user accounts and computer accounts. Silo members are technically blocked from obtaining Kerberos tickets (TGT/TGS) to authenticate to hosts outside the silo.
2. **Shortens Session Exposure**: Authentication policies can restrict Kerberos Ticket Granting Ticket (TGT) lifetimes for silo members (e.g., down to 120 minutes), minimizing the window of exposure for hijacked sessions.
3. **Cryptographic Validation**: Uses Kerberos claims and Dynamic Access Control (DAC) to dynamically evaluate and enforce authentication paths at the domain controller level.

---

## Legacy Impact & Compatibility
* **Protected Users Prerequisite**: Users placed in an Authentication Silo must also be members of the **Protected Users** security group. Silos apply only to the Kerberos protocol; if NTLM is not blocked for these users, the silo restrictions can be bypassed using NTLM fallbacks.
* **Domain Functional Level (DFL)**: The AD environment must be at a minimum functional level of Windows Server 2012 R2.
* **Strict Lockout Risk**: If a Tier 0 administrator tries to log on to a PAW that has not been explicitly added to the Tier 0 Silo, their logon attempt will be rejected by the Domain Controller. Administrators must ensure all management hosts are enrolled in the silo before enforcing the policy.

---

## Implementation Steps

### Option A: Active Directory Administrative Center (ADAC) Configuration

#### 1. Enable KDC Claims and Armoring via Group Policy
Before configuring silos, Domain Controllers must be configured to support claims:

1. Open **Group Policy Management** (`gpmc.msc`).
2. Edit the GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\KDC`
4. Double-click the **Support for claims, compound authentication and Kerberos armoring** policy.
5. Set it to **Enabled**.
6. Under options, select **Supported** (or **Always support**).
7. Save the GPO and run `gpupdate /force` on all Domain Controllers.

#### 2. Create the Authentication Policy and Silo in ADAC
1. Open **Active Directory Administrative Center** (`dsac.exe`).
2. In the left pane, click the tree view, expand your domain, and select the **Authentication** container.
3. Right-click **Authentication Policies**, click **New**, and then click **Authentication Policy**:
   * **Name**: `T0_AuthPol`
   * Check **Enforce user ticket lifetime restrictions** and set the TGT lifetime value to `120` minutes.
4. Right-click **Authentication Policy Silos**, click **New**, and then click **Authentication Policy Silo**:
   * **Name**: `T0_Silo`
   * Select **Enforce the silo policies**.
   * Under **Permitted Accounts**, click **Add** to specify the user accounts and computer objects (PAWs and DCs) that belong to Tier 0.
   * Under the **User** policy, select `T0_AuthPol`. Under the **Computer** policy, select `T0_AuthPol`.
5. Click **OK** to save and apply the Silo.

---

### Option B: PowerShell Configuration (Remediation / Non-GPO)

Run the following script block to programmatically define the Authentication Policy, create the Silo, and enroll Tier 0 members.

[Download Script: Set-ADAuthenticationSilo.ps1](implementation_scripts/Set-ADAuthenticationSilo.ps1)

```powershell
# Set-ADAuthenticationSilo.ps1
# Description: Creates a Tier 0 Authentication Policy Silo and assigns accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Configure Active Directory Authentication Silos..." -ForegroundColor Cyan

$PolicyName = "T0_AuthPol"
$SiloName = "T0_Silo"
$UserGroupName = "Grp_Tier0_Admins"   # AD group containing Tier 0 admin users
$ComputerGroupName = "Grp_Tier0_PAWs" # AD group containing Tier 0 PAW computers

# 1. Create the Authentication Policy if it does not exist
$ExistPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$PolicyName'" -ErrorAction SilentlyContinue

if (-not $ExistPolicy) {
    # Create policy with 120-minute (2 hour) TGT lifetime
    New-ADAuthenticationPolicy -Name $PolicyName `
        -Description "Authentication Policy for Tier 0 Administrators" `
        -UserTGTLifetimeMins 120 `
        -Enforce $true `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy '$PolicyName' created." -ForegroundColor Green
} else {
    Write-Host "[*] Authentication Policy '$PolicyName' already exists." -ForegroundColor Yellow
}

# 2. Create the Authentication Policy Silo
$ExistSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$SiloName'" -ErrorAction SilentlyContinue

if (-not $ExistSilo) {
    New-ADAuthenticationPolicySilo -Name $SiloName `
        -Description "Authentication Policy Silo for Tier 0 Containment" `
        -UserAuthenticationPolicy $PolicyName `
        -ComputerAuthenticationPolicy $PolicyName `
        -ServiceAuthenticationPolicy $PolicyName `
        -Enforce $true `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy Silo '$SiloName' created." -ForegroundColor Green
} else {
    Write-Host "[*] Authentication Policy Silo '$SiloName' already exists." -ForegroundColor Yellow
}

# 3. Grant Silo Access to Users and Computers
Write-Host "Granting silo access to members of group '$UserGroupName'..." -ForegroundColor White
$AdminUsers = Get-ADGroupMember -Identity $UserGroupName -Recursive | Where-Object { $_.objectClass -eq "user" }
foreach ($User in $AdminUsers) {
    Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $User.DistinguishedName -ErrorAction SilentlyContinue
    Set-ADAccountAuthenticationPolicySilo -Identity $User.DistinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
}

Write-Host "Granting silo access to members of group '$ComputerGroupName'..." -ForegroundColor White
$PawComputers = Get-ADGroupMember -Identity $ComputerGroupName -Recursive | Where-Object { $_.objectClass -eq "computer" }
foreach ($Comp in $PawComputers) {
    Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $Comp.DistinguishedName -ErrorAction SilentlyContinue
    Set-ADAccountAuthenticationPolicySilo -Identity $Comp.DistinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
}

# 4. Grant access to Domain Controllers (writable DCs must be part of the silo)
$DCs = Get-ADDomainController -Filter "IsReadOnly -eq `$false"
foreach ($DC in $DCs) {
    $DcDN = $DC.ComputerObjectDN
    Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $DcDN -ErrorAction SilentlyContinue
    Set-ADAccountAuthenticationPolicySilo -Identity $DcDN -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
}

Write-Host "[+] Authentication Silo membership initialized." -ForegroundColor Green
```

*To verify active Authentication Silo status:*
[Download Script: Get-AuthSiloAuditStatus.ps1](audit_scripts/Get-AuthSiloAuditStatus.ps1)

```powershell
# Get-AuthSiloAuditStatus.ps1
# Description: Queries the active Authentication Silos and lists their configuration settings.

Import-Module ActiveDirectory

Write-Host "--- Auditing Authentication Silos ---" -ForegroundColor Cyan

$Silos = Get-ADAuthenticationPolicySilo -Filter * -Properties *

if ($Silos) {
    foreach ($Silo in $Silos) {
        Write-Host "[+] Silo Name: $($Silo.Name)" -ForegroundColor Green
        Write-Host "    - Enforced: $($Silo.Enforce)" -ForegroundColor White
        Write-Host "    - User Policy: $($Silo.UserAuthenticationPolicy)" -ForegroundColor White
        Write-Host "    - Computer Policy: $($Silo.ComputerAuthenticationPolicy)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No Authentication Policy Silos configured in this domain." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendations R8, R64, R80, Annexe C (Mise en œuvre d'un silo)
* **ANSSI Remediation of Active Directory Tier 0 Guide**: Section 10.g (Page 40), Section 11 (Page 49)
* **Microsoft Security Guidance**: Authentication Policies and Authentication Policy Silos Overview
