# [REQ-OPS-006] Redirect Default Users and Computers Containers

## Target Scope
* **Applicable Systems**: Active Directory Domain Controllers (Domain-wide structural policy)
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025
* **Domain Functional Level**: Windows Server 2003 or higher

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Domain Well-Known Objects (`wellKnownObjects` attribute on domain head `DC=domain,DC=com`)
  * **Default Users WKGUID**: `a9d1ca1576e611d182220000f87a39b2` (`GUID_USERS_CONTAINER_W`)
  * **Default Computers WKGUID**: `aa31290876e611d182220000f87a39b2` (`GUID_COMPUTERS_CONTAINER_W`)
  * **Administrative Utilities**: `redircmp.exe`, `redirusr.exe`

---

## Rationale

In default Active Directory deployments, newly provisioned user and computer accounts are automatically instantiated within two legacy default containers located at the root of the domain:
* **Default Users Container**: `CN=Users,DC=domain,DC=com`
* **Default Computers Container**: `CN=Computers,DC=domain,DC=com`

From an enterprise security and systems architecture perspective, placing active operational assets in these default locations creates severe defensive gaps, policy blind spots, and lateral movement vulnerabilities.

### 1. The Container vs. Organizational Unit (OU) Schema Barrier

The fundamental architectural weakness of default containers stems from their Active Directory schema definition:
* `CN=Users` and `CN=Computers` possess the schema class `container` (`objectClass: container`).
* Group Policy Objects (GPOs) **cannot** be linked to generic containers. Under the Active Directory directory service architecture, the `gPLink` and `gPOptions` attributes are valid only on Site objects (`site`), Domain heads (`domainDNS`), and Organizational Units (`organizationalUnit`).

Consequently, any newly joined computer or freshly created user placed in `CN=Computers` or `CN=Users` inherits **only the Default Domain Policy**. They bypass all targeted organizational security baselines until an administrator manually identifies the object and moves it to a hardened OU.

### 2. The "Staging Exposure Window" Threat Vector

The operational interval between initial computer domain join (or user creation) and subsequent administrative relocation is known as the **staging exposure window**. During this window, systems run in an unhardened, highly vulnerable state:
* **Missing Endpoint Isolation**: Member workstations and servers do not receive endpoint firewall rules blocking inbound RPC, SMB, and WinRM management traffic from peer endpoints (violating [REQ-NET-003](../04-network-firewall/configure-workstation-isolation.md)).
* **Disabled Credential Protections**: Critical safeguards such as Windows Defender Credential Guard, LSA Protection in RunAsPPL mode ([REQ-DC-016](../02-domain-controllers/enable-lsa-protection.md)), and WDigest credential caching disabling remain unenforced.
* **Unmanaged Local Administrator Passwords**: Windows LAPS policies ([REQ-ID-002](../03-identities-services/enable-laps.md)) are not applied to generic containers. If imaging tools or provisioning workflows assign a standard default local administrator password, that password remains active and identical across newly deployed endpoints, exposing the enterprise to instant pass-the-hash lateral expansion.
* **Absence of Application Control & Attack Surface Reduction**: AppLocker / Windows Defender Application Control (WDAC) rules, as well as Defender Exploit Guard / Attack Surface Reduction (ASR) rules, do not execute.
* **Audit and Telemetry Gaps**: Advanced Security Audit Policies ([REQ-LOG-001](../05-logging-monitoring/configure-advanced-audit-policies.md)) and Sysmon configurations ([REQ-LOG-003](../05-logging-monitoring/deploy-and-harden-sysmon.md)) are absent, blinding the Security Operations Center (SOC) during the critical commissioning phase.

### 3. Machine Account Quota & Unauthorized Domain Join Exploitation

When Active Directory environments permit standard authenticated users to join systems to the domain via `ms-DS-MachineAccountQuota` (see [REQ-ID-017](../03-identities-services/disable-machine-account-quota.md)), newly created machine accounts default to `CN=Computers`.

Adversaries possessing compromised low-privilege user credentials exploit this behavior to:
1. Programmatically join rogue virtual machines or spoofed computer accounts to the domain.
2. Exploit the absence of GPO restrictions on `CN=Computers` to establish persistence or request Kerberos Service Principal Names (SPNs).
3. Stage Resource-Based Constrained Delegation (RBCD) attacks, abusing machine accounts in default containers to achieve privilege escalation against misconfigured hosts.

Redirecting `CN=Computers` to an Organizational Unit that has strict access control lists (ACLs) prevents unprivileged accounts from creating machine objects unless explicit permissions are delegated, reinforcing the requirement to set `ms-DS-MachineAccountQuota` to `0`.

### 4. Enterprise Access Model & Tiering Integrity

In a tiered administrative architecture (Enterprise Access Model / Tier 0, Tier 1, Tier 2), assets must be strictly partitioned:
* Unassigned systems landing in generic root containers break boundary enforcement.
* Helpdesk technicians or Tier 2 operators granted delegation over `CN=Computers` may inadvertently gain control over staging Tier 1 application servers or Tier 0 infrastructure components.
* Moving objects to designated staging OUs ensures that only authorized staging and deployment engineers have management authority during the provisioning lifecycle.

### 5. Accidental Deletion Mitigation

Generic container objects do not support the Active Directory GUI accidental deletion protection flag out of the box in the same granular manner as Organizational Units. Creating dedicated Organizational Units and configuring `ProtectedFromAccidentalDeletion = $true` ensures that neither the staging containers nor child objects can be deleted through administrative accident or reckless scripting.

```
+---------------------------------------------------------------------------------------------------+
| Active Directory Root Domain (DC=domain,DC=local)                                                 |
+---------------------------------------------------------------------------------------------------+
       |
       +---> [DEFAULT BEHAVIOR - UNSECURE]
       |     +-------------------------------------------------------------------------------------+
       |     | CN=Computers (objectClass: container)                                              |
       |     |   * No GPOs can be linked (gPLink invalid)                                          |
       |     |   * Windows LAPS, Credential Guard, Firewall, and AppLocker UNENFORCED              |
       |     |   * Broad "Authenticated Users" write permissions if MachineAccountQuota > 0       |
       |     +-------------------------------------------------------------------------------------+
       |
       +---> [HARDENED REDIRECTION - SECURE]
             +-------------------------------------------------------------------------------------+
             | OU=Staging-Computers (objectClass: organizationalUnit)                              |
             |   * Accidental Deletion Protection ENABLED                                          |
             |   * Linked GPO: Quarantine Baseline (Inbound Firewall Blocked, LAPS Enforced)      |
             |   * Strict ACLs: Only Authorized Provisioning Service Accounts / Admins            |
             |                                                                                     |
             | OU=Staging-Users (objectClass: organizationalUnit)                                  |
             |   * Accidental Deletion Protection ENABLED                                          |
             |   * Linked GPO: User Quarantine Baseline (Smart Card/MFA Enforced, Deny Dial-in)    |
             |   * Strict ACLs: Dedicated HR Sync / Provisioning Delegations                      |
             +-------------------------------------------------------------------------------------+
```

---

## Legacy Impact & Compatibility

* **Unprivileged Domain Join Permissions**: Under default AD behavior, standard users can join up to 10 computers to `CN=Computers` because `Authenticated Users` possess the `Create Computer Objects` permission on that container. When `CN=Computers` is redirected to an OU, standard users will **not** possess creation rights on the target OU by default. 
  * *Operational Alignment*: This is the intended security design. In accordance with [[REQ-ID-017] Disable Machine Account Quota](../03-identities-services/disable-machine-account-quota.md), standard users must never join arbitrary machines to the domain. Only designated automated provisioning accounts or delegated administrators should perform domain joins.
* **Microsoft KB5020276 / CVE-2022-38042 Netjoin Hardening**: Microsoft cumulative updates introduce strict owner checks during domain join operations. When re-joining or pre-staging computer accounts in the redirected OU, the joining identity must either be the creator/owner (`mS-DS-CreatorSID`) or possess explicit permissions to reuse the account.
* **Hardcoded LDAP Provisioning Queries**: Legacy line-of-business software, automated HR onboarding scripts, Identity Management (IdM) platforms, Entra ID Connect (Azure AD Connect), or mobile device enrollment systems that hardcode search bases to `CN=Users,DC=domain,DC=com` or `CN=Computers,DC=domain,DC=com` will not locate newly created accounts.
  * *Resolution*: Update identity synchronization filters and provisioning scripts to query the domain root with a subtree search scope (`LDAP_SCOPE_SUBTREE`) or point explicitly to the new staging OUs.
* **Existing Directory Objects**: Executing `redircmp.exe` and `redirusr.exe` modifies only the default creation targets for *future* objects. It does **not** move existing objects currently residing in `CN=Users` or `CN=Computers`.
* **Built-in System Accounts & Security Principals**:
  * Default built-in user accounts (`Administrator`, `Guest`, `krbtgt`) and default built-in groups (`Domain Admins`, `Enterprise Admins`, `Domain Users`, `Domain Computers`) must remain in `CN=Users`. Moving default built-in security principals out of `CN=Users` is unsupported by Microsoft and can cause directory service or tool failures.
  * Redirection specifically isolates newly provisioned accounts from these built-in principals.
* **Domain Controller Promotions**: When a member server is promoted to a Domain Controller (`Install-ADDSDomainController` or `dcpromo`), the Active Directory directory service engine automatically relocates the machine account to `OU=Domain Controllers,DC=domain,DC=com` (governed by `GUID_DOMAIN_CONTROLLERS_CONTAINER_W`). Container redirection does not interfere with DC promotion.

---

## Implementation Steps

### Option A: Active Directory Administrative Center & Native CLI Tools (Preferred)

Execute the following procedure on a Domain Controller using an account with **Domain Admins** or **Enterprise Admins** privileges.

#### 1. Create and Protect Staging Organizational Units

1. Open **Active Directory Administrative Center** (`dsac.exe`) or **Active Directory Users and Computers** (`dsa.msc`).
2. Ensure **View -> Advanced Features** is enabled in `dsa.msc`.
3. Create two dedicated staging Organizational Units at the appropriate administrative level (e.g., at the domain root or under a dedicated `Staging` hierarchy):
   * `OU=Staging-Computers,DC=domain,DC=com`
   * `OU=Staging-Users,DC=domain,DC=com`
4. For both OUs, verify that accidental deletion protection is active:
   * Right-click the OU, select **Properties**, navigate to the **Object** tab.
   * Verify that **Protect object from accidental deletion** is checked. Click **OK**.

#### 2. Link Baseline Quarantine Group Policy Objects

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create and link a dedicated quarantine baseline GPO to `OU=Staging-Computers`:
   * Enforce Windows LAPS with randomized high-entropy passwords.
   * Enable Windows Firewall for all profiles with default inbound block rules, permitting only essential management traffic from authorized deployment servers and DCs.
   * Enable Windows Defender Antivirus real-time protection and Credential Guard.
3. Link appropriate baseline policies to `OU=Staging-Users` (e.g., enforce Kerberos pre-authentication, smart card enforcement, or account disablement pending onboarding validation).

#### 3. Execute Container Redirection

1. Open an elevated Command Prompt (`cmd.exe`) on a Domain Controller.
2. Redirect the default computer container to the new staging OU:
   ```cmd
   redircmp.exe "OU=Staging-Computers,DC=domain,DC=com"
   ```
   *(Replace `DC=domain,DC=com` with the actual Distinguished Name of the domain).*
3. Verify command output:
   ```text
   Redirection was successful.
   ```
4. Redirect the default user container to the new staging OU:
   ```cmd
   redirusr.exe "OU=Staging-Users,DC=domain,DC=com"
   ```
   *(Replace `DC=domain,DC=com` with the actual Distinguished Name of the domain).*
5. Verify command output:
   ```text
   Redirection was successful.
   ```

#### 4. Delegate Computer Joining Permissions on Staging-Computers OU

If authorized provisioning accounts or automated imaging systems (SCCM/MECM, MDT, WDS) need to join computers:
1. In `dsa.msc`, right-click `OU=Staging-Computers` and select **Delegate Control...**.
2. Add the designated provisioning service account or security group (e.g., `SVC_ComputerJoiner_gMSA` or `GG_Workstation_Provisioning`).
3. Select **Create a custom task to delegate** -> **Next**.
4. Select **Only the following objects in the folder** -> check **Computer objects** -> check **Create selected objects in this folder**.
5. Click **Next**, grant `Read` and `Write` permissions for computer properties, and finish the wizard.

---

### Option B: PowerShell Automated Administration (Audit & Remediation)

The following PowerShell scripts run natively on **Windows PowerShell 5.1** on Domain Controllers with the Active Directory RSAT module installed.

#### 1. Local Audit (Audit-DefaultContainers.ps1)

This script audits the redirection state of both user and computer containers, validates accidental deletion protection, verifies GPO linkages, and flags any unmanaged residual accounts remaining in legacy containers.

[Download Script: Audit-DefaultContainers.ps1](audit_scripts/Audit-DefaultContainers.ps1)

```powershell
# Audit-DefaultContainers.ps1
# Description: Audits Active Directory default user and computer container redirection,
#              verifies accidental deletion protection, checks GPO linkage, and inventories residual accounts.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Active Directory Default Containers Redirection ---" -ForegroundColor Cyan

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "VULNERABLE: The ActiveDirectory PowerShell module is not installed or available on this system." -ForegroundColor Red
    exit 1
}

Import-Module ActiveDirectory

$isVulnerable = $false

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName
    $defaultComputersDN = "CN=Computers,$($domainDN)"
    $defaultUsersDN = "CN=Users,$($domainDN)"

    Write-Host "[i] Domain Distinguished Name: $($domainDN)" -ForegroundColor Gray
    Write-Host "[i] Domain Functional Level : $($domain.DomainMode)" -ForegroundColor Gray
    Write-Host ""

    # -------------------------------------------------------------
    # 2. Check Computers Container Redirection
    # -------------------------------------------------------------
    Write-Host "Checking Computers Container Configuration..." -ForegroundColor Yellow
    $currentCompContainer = $domain.ComputersContainer
    Write-Host "[i] Current Computers Container: $($currentCompContainer)" -ForegroundColor Gray

    if ($currentCompContainer -eq $defaultComputersDN) {
        Write-Host "VULNERABLE: Default Computers container is NOT redirected. Newly joined computers land in unmanaged 'CN=Computers'." -ForegroundColor Red
        $isVulnerable = $true
    } else {
        # Verify the redirected container is an OU
        $compTarget = Get-ADObject -Identity $currentCompContainer -Properties ProtectedFromAccidentalDeletion, gPLink -ErrorAction SilentlyContinue
        if ($null -eq $compTarget) {
            Write-Host "VULNERABLE: The redirected Computers target container does not exist: $($currentCompContainer)" -ForegroundColor Red
            $isVulnerable = $true
        } elseif ($compTarget.ObjectClass -ne "organizationalUnit") {
            Write-Host "VULNERABLE: Computers container is redirected to object class '$($compTarget.ObjectClass)', NOT an Organizational Unit. GPOs cannot be linked directly." -ForegroundColor Red
            $isVulnerable = $true
        } else {
            Write-Host "[+] Computers container is redirected to an Organizational Unit." -ForegroundColor Green

            # Check accidental deletion protection
            if ($compTarget.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Computers OU has Accidental Deletion Protection ENABLED." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Computers OU '$($compTarget.Name)' has Accidental Deletion Protection DISABLED." -ForegroundColor Red
                $isVulnerable = $true
            }

            # Check GPO linkage
            if ([string]::IsNullOrEmpty($compTarget.gPLink)) {
                Write-Host "WARNING: Computers target OU has NO Group Policy Objects linked. Newly joined machines will not receive hardening baselines." -ForegroundColor Yellow
            } else {
                Write-Host "[+] Computers target OU has active Group Policy Object(s) linked." -ForegroundColor Green
            }
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 3. Check Users Container Redirection
    # -------------------------------------------------------------
    Write-Host "Checking Users Container Configuration..." -ForegroundColor Yellow
    $currentUserContainer = $domain.UsersContainer
    Write-Host "[i] Current Users Container: $($currentUserContainer)" -ForegroundColor Gray

    if ($currentUserContainer -eq $defaultUsersDN) {
        Write-Host "VULNERABLE: Default Users container is NOT redirected. Newly created users land in unmanaged 'CN=Users'." -ForegroundColor Red
        $isVulnerable = $true
    } else {
        # Verify the redirected container is an OU
        $userTarget = Get-ADObject -Identity $currentUserContainer -Properties ProtectedFromAccidentalDeletion, gPLink -ErrorAction SilentlyContinue
        if ($null -eq $userTarget) {
            Write-Host "VULNERABLE: The redirected Users target container does not exist: $($currentUserContainer)" -ForegroundColor Red
            $isVulnerable = $true
        } elseif ($userTarget.ObjectClass -ne "organizationalUnit") {
            Write-Host "VULNERABLE: Users container is redirected to object class '$($userTarget.ObjectClass)', NOT an Organizational Unit. GPOs cannot be linked directly." -ForegroundColor Red
            $isVulnerable = $true
        } else {
            Write-Host "[+] Users container is redirected to an Organizational Unit." -ForegroundColor Green

            # Check accidental deletion protection
            if ($userTarget.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Users OU has Accidental Deletion Protection ENABLED." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Users OU '$($userTarget.Name)' has Accidental Deletion Protection DISABLED." -ForegroundColor Red
                $isVulnerable = $true
            }

            # Check GPO linkage
            if ([string]::IsNullOrEmpty($userTarget.gPLink)) {
                Write-Host "WARNING: Users target OU has NO Group Policy Objects linked. Newly provisioned users will not receive hardening baselines." -ForegroundColor Yellow
            } else {
                Write-Host "[+] Users target OU has active Group Policy Object(s) linked." -ForegroundColor Green
            }
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 4. Inventory Residual Accounts in Legacy Containers
    # -------------------------------------------------------------
    Write-Host "Inventorying Residual Non-Built-in Objects in Default Containers..." -ForegroundColor Yellow

    # Residual computers in CN=Computers
    $strayComputers = Get-ADComputer -SearchBase $defaultComputersDN -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue
    if ($strayComputers) {
        $count = ($strayComputers | Measure-Object).Count
        Write-Host "WARNING: Found $($count) computer object(s) remaining in legacy default 'CN=Computers'. These should be migrated to appropriate tier OUs." -ForegroundColor Yellow
        foreach ($comp in $strayComputers | Select-Object -First 5) {
            Write-Host "  - $($comp.Name) (Enabled: $($comp.Enabled))" -ForegroundColor Gray
        }
        if ($count -gt 5) {
            Write-Host "  - ... and $($count - 5) more computer(s)." -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] Legacy default 'CN=Computers' container has no residual computer objects." -ForegroundColor Green
    }

    # Residual non-system users in CN=Users
    $builtinSids = @(
        "$($domain.DomainSID)-500", # Administrator
        "$($domain.DomainSID)-501", # Guest
        "$($domain.DomainSID)-502"  # krbtgt
    )
    $strayUsers = Get-ADUser -SearchBase $defaultUsersDN -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue | Where-Object {
        $builtinSids -notcontains $_.SID.Value -and $_.SamAccountName -ne "SUPPORT_388945a0"
    }
    if ($strayUsers) {
        $userCount = ($strayUsers | Measure-Object).Count
        Write-Host "WARNING: Found $($userCount) non-built-in user account(s) remaining in legacy default 'CN=Users'. These should be evaluated and migrated to tier OUs." -ForegroundColor Yellow
        foreach ($usr in $strayUsers | Select-Object -First 5) {
            Write-Host "  - $($usr.SamAccountName) (Enabled: $($usr.Enabled))" -ForegroundColor Gray
        }
        if ($userCount -gt 5) {
            Write-Host "  - ... and $($userCount - 5) more user(s)." -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] Legacy default 'CN=Users' container contains only default built-in security principals." -ForegroundColor Green
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 5. Final Compliance Assessment
    # -------------------------------------------------------------
    if ($isVulnerable) {
        Write-Host "STATUS: NON-COMPLIANT - Default container redirection is not fully configured or protected." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "STATUS: COMPLIANT - Default Users and Computers containers are properly redirected to deletion-protected Organizational Units." -ForegroundColor Green
        exit 0
    }

} catch {
    Write-Host "VULNERABLE: Failed to query Active Directory domain configuration. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

#### 2. Local Remediation (Set-DefaultContainersRedirection.ps1)

This script creates the target staging Organizational Units, enables accidental deletion protection, executes `redircmp.exe` and `redirusr.exe`, and verifies the updated well-known objects in Active Directory.

[Download Script: Set-DefaultContainersRedirection.ps1](implementation_scripts/Set-DefaultContainersRedirection.ps1)

```powershell
# Set-DefaultContainersRedirection.ps1
# Description: Creates staging OUs, configures accidental deletion protection,
#              and redirects default user and computer containers using redircmp and redirusr.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [string]$TargetComputersOUName = "Staging-Computers",

    [Parameter(Mandatory = $false)]
    [string]$TargetUsersOUName = "Staging-Users",

    [Parameter(Mandatory = $false)]
    [string]$ParentOUPath
)

Write-Host "--- Applying Hardening: Redirect Default Users and Computers Containers ---" -ForegroundColor Cyan

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    exit 1
}

Import-Module ActiveDirectory

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName

    # Determine base path
    if ([string]::IsNullOrEmpty($ParentOUPath)) {
        $basePath = $domainDN
    } else {
        $basePath = $ParentOUPath
    }

    $targetComputersDN = "OU=$($TargetComputersOUName),$($basePath)"
    $targetUsersDN = "OU=$($TargetUsersOUName),$($basePath)"

    Write-Host "[i] Target Computers OU DN: $($targetComputersDN)" -ForegroundColor Gray
    Write-Host "[i] Target Users OU DN    : $($targetUsersDN)" -ForegroundColor Gray
    Write-Host ""

    # -------------------------------------------------------------
    # 2. Provision and Protect Computers Staging OU
    # -------------------------------------------------------------
    $existingCompOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($targetComputersDN)'" -ErrorAction SilentlyContinue
    if ($null -eq $existingCompOU) {
        if ($PSCmdlet.ShouldProcess($targetComputersDN, "Create Organizational Unit and enable Accidental Deletion Protection")) {
            Write-Host "[+] Creating target Computers OU: $($targetComputersDN)" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $TargetComputersOUName -Path $basePath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Target Computers OU created and protected successfully." -ForegroundColor Green
        }
    } else {
        Write-Host "[+] Target Computers OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($targetComputersDN, "Set ProtectedFromAccidentalDeletion = $true")) {
            Set-ADOrganizationalUnit -Identity $targetComputersDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Accidental deletion protection verified on Computers OU." -ForegroundColor Green
        }
    }

    # -------------------------------------------------------------
    # 3. Provision and Protect Users Staging OU
    # -------------------------------------------------------------
    $existingUserOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($targetUsersDN)'" -ErrorAction SilentlyContinue
    if ($null -eq $existingUserOU) {
        if ($PSCmdlet.ShouldProcess($targetUsersDN, "Create Organizational Unit and enable Accidental Deletion Protection")) {
            Write-Host "[+] Creating target Users OU: $($targetUsersDN)" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $TargetUsersOUName -Path $basePath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Target Users OU created and protected successfully." -ForegroundColor Green
        }
    } else {
        Write-Host "[+] Target Users OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($targetUsersDN, "Set ProtectedFromAccidentalDeletion = $true")) {
            Set-ADOrganizationalUnit -Identity $targetUsersDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Accidental deletion protection verified on Users OU." -ForegroundColor Green
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 4. Redirect Computers Container via redircmp.exe
    # -------------------------------------------------------------
    if ($domain.ComputersContainer -ne $targetComputersDN) {
        if ($PSCmdlet.ShouldProcess($domainDN, "Redirect Computers Container to $($targetComputersDN)")) {
            Write-Host "[+] Redirecting default Computers container to: $($targetComputersDN)..." -ForegroundColor Yellow
            $outputComp = & redircmp.exe $targetComputersDN 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] redircmp output: $($outputComp)" -ForegroundColor Green
            } else {
                throw "redircmp.exe failed with exit code $($LASTEXITCODE). Output: $($outputComp)"
            }
        }
    } else {
        Write-Host "[+] Computers container is already redirected to target OU: $($targetComputersDN)" -ForegroundColor Green
    }

    # -------------------------------------------------------------
    # 5. Redirect Users Container via redirusr.exe
    # -------------------------------------------------------------
    if ($domain.UsersContainer -ne $targetUsersDN) {
        if ($PSCmdlet.ShouldProcess($domainDN, "Redirect Users Container to $($targetUsersDN)")) {
            Write-Host "[+] Redirecting default Users container to: $($targetUsersDN)..." -ForegroundColor Yellow
            $outputUser = & redirusr.exe $targetUsersDN 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] redirusr output: $($outputUser)" -ForegroundColor Green
            } else {
                throw "redirusr.exe failed with exit code $($LASTEXITCODE). Output: $($outputUser)"
            }
        }
    } else {
        Write-Host "[+] Users container is already redirected to target OU: $($targetUsersDN)" -ForegroundColor Green
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 6. Post-Remediation Verification
    # -------------------------------------------------------------
    $refreshedDomain = Get-ADDomain -ErrorAction Stop
    Write-Host "Post-Remediation Verification:" -ForegroundColor Cyan
    Write-Host "  - Domain ComputersContainer: $($refreshedDomain.ComputersContainer)" -ForegroundColor Gray
    Write-Host "  - Domain UsersContainer    : $($refreshedDomain.UsersContainer)" -ForegroundColor Gray

    if ($refreshedDomain.ComputersContainer -eq $targetComputersDN -and $refreshedDomain.UsersContainer -eq $targetUsersDN) {
        Write-Host "`n[+] Default containers redirection completed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Directory attributes have not yet reflected the redirection. Allow time for domain-wide replication."
    }

    Write-Host ""
    Write-Host "[IMPORTANT NEXT STEPS]:" -ForegroundColor Yellow
    Write-Host "1. Link a quarantine/staging Group Policy Object (GPO) to '$($targetComputersDN)' (enforcing LAPS, Firewall, Credential Guard)." -ForegroundColor Gray
    Write-Host "2. Delegate 'Create Computer Objects' on '$($targetComputersDN)' to authorized provisioning service accounts." -ForegroundColor Gray
    Write-Host "3. Inventory and migrate any non-built-in residual accounts from 'CN=Computers' and 'CN=Users' to appropriate production OUs." -ForegroundColor Gray

} catch {
    Write-Error "Remediation failed. Error: $($_.Exception.Message)"
    exit 1
}
```

---

## Sources & Compliance References
* **Microsoft Learn - Administrative Reference**: [Redirecting the Users and Computers Containers in Active Directory Domains](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers)
* **ANSSI Hardening Active Directory**: [Recommendation R63 - Partitionnement logique et structure de l'annuaire (Securing Directory Structure and Delegation)](https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-active-directory)
* **CIS Microsoft Windows Server Benchmark**: Section on Active Directory Administrative Infrastructure and Organizational Unit Structure
* **Microsoft Security Guidance**: [KB5020276 - Netjoin: Domain Join Hardening Changes (CVE-2022-38042)](https://support.microsoft.com/en-us/topic/kb5020276-netjoin-domain-join-hardening-changes-c39fb260-e63f-4599-ac3d-025505d96750)
* **Related Hardening Control**: [[REQ-ID-017] Disable Machine Account Quota (`ms-DS-MachineAccountQuota`)](../03-identities-services/disable-machine-account-quota.md)
