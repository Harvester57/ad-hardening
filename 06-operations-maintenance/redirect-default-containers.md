# [REQ-OPS-006] Redirect Default Users and Computers Containers

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**: Active Directory Domain Well-Known Objects

---

## Rationale
By default, new user and computer objects created in an Active Directory domain are placed in the default containers:
* **Users**: `CN=Users,DC=domain,DC=com`
* **Computers**: `CN=Computers,DC=domain,DC=com`

These default paths present significant security and operational issues:
1. **Lack of GPO Enforcement**: Default containers are generic container objects, not Organizational Units (OUs). Consequently, Group Policy Objects (GPOs) cannot be linked directly to them. Any newly joined computer or newly created user remains unhardened and outside the scope of organizational baseline policies until an administrator manually moves them to an OU.
2. **Insecure Window of Exposure**: The period between the initial domain join/creation and the manual movement of the object creates a window of vulnerability where systems run without mandatory security controls (e.g., endpoint firewall rules, AppLocker, audit configurations, credential protection).
3. **Absence of Deletion Protection**: Default containers do not possess the standard accidental deletion protection attributes that can be applied to OUs, increasing the risk of administrative errors.

Redirecting the default creation paths of users and computers to dedicated, hardened OUs ensures that newly created objects immediately inherit appropriate GPOs and are protected against accidental deletion from the moment of creation.

---

## Legacy Impact & Compatibility
* **Domain Join Permissions**: Under default AD behavior, authenticated users can join up to 10 computer objects to the domain in the `CN=Computers` container (subject to `ms-DS-MachineAccountQuota`). When `CN=Computers` is redirected to an OU, standard users will lack the permission to create computer objects in that new OU by default. However, since the Machine Account Quota is disabled (`ms-DS-MachineAccountQuota` set to `0` as per [[REQ-ID-017]](../03-identities-services/disable-machine-account-quota.md)), only delegated administrators can join systems, making this change consistent with the overall security model.
* **Legacy Application Mappings**: Some legacy line-of-business applications, provisioning scripts, or identity synchronizers (such as old Entra Connect/Azure AD Connect configurations) might be hardcoded to query or write to `CN=Users` or `CN=Computers`. These systems must be audited and updated to reference the new OUs before enabling redirection.
* **Domain Functional Level**: The Active Directory domain functional level must be Windows Server 2003 or higher to support redirection.

---

## Implementation Steps

### Option A: Active Directory Administrative Tools & CLI (Preferred)

1. Log on to a Domain Controller or a management host with **Domain Admins** or **Enterprise Admins** credentials.
2. Open **Active Directory Users and Computers** (`dsa.msc`).
3. Create two new Organizational Units (OUs) at the domain root:
   * **Name**: `New-Users`
   * **Name**: `New-Computers`
4. For both OUs, ensure that accidental deletion protection is enabled:
   * Right-click the OU, select **Properties**.
   * Navigate to the **Object** tab (ensure **View -> Advanced Features** is enabled in `dsa.msc` to see this tab).
   * Check **Protect object from accidental deletion** and click **OK**.
5. Open an elevated command prompt on a Domain Controller.
6. Run the following command to redirect the default container for new computer objects:
   ```cmd
   redircmp.exe OU=New-Computers,DC=domain,DC=local
   ```
   *(Replace `DC=domain,DC=local` with the actual Distinguished Name of your domain).*
7. Run the following command to redirect the default container for new user objects:
   ```cmd
   redirusr.exe OU=New-Users,DC=domain,DC=local
   ```
   *(Replace `DC=domain,DC=local` with the actual Distinguished Name of your domain).*
8. Verify that the output of both commands states: `Redirection was successful.`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts on a Domain Controller or administrative system with remote AD management tools.

#### 1. Local Audit

[Download Script: Audit-DefaultContainers.ps1](audit_scripts/Audit-DefaultContainers.ps1)

```powershell
# Audit-DefaultContainers.ps1
# Description: Audits if the default user and computer containers have been redirected to protected OUs.

Import-Module ActiveDirectory

Write-Host "--- Auditing Default User and Computer Containers Redirection ---" -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName
    $DefaultComputersDN = "CN=Computers,$($DomainDN)"
    $DefaultUsersDN = "CN=Users,$($DomainDN)"
    
    $Compliant = $true
    
    # 1. Check Computers Container
    Write-Host "[+] Current Computers Container: $($Domain.ComputersContainer)" -ForegroundColor Gray
    if ($Domain.ComputersContainer -eq $DefaultComputersDN) {
        Write-Host "VULNERABLE: Default Computers container is NOT redirected." -ForegroundColor Red
        $Compliant = $false
    } else {
        # Verify the redirected container is an OU and is protected from deletion
        $CompOU = Get-ADOrganizationalUnit -Identity $Domain.ComputersContainer -Properties ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue
        if ($CompOU) {
            if ($CompOU.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Computers Container redirected to a protected OU (Compliant)." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Computers Container redirected to OU '$($CompOU.Name)' but Accidental Deletion Protection is DISABLED." -ForegroundColor Red
                $Compliant = $false
            }
        } else {
            Write-Host "VULNERABLE: Computers Container is redirected to a non-OU object or the target container does not exist." -ForegroundColor Red
            $Compliant = $false
        }
    }
    
    # 2. Check Users Container
    Write-Host "[+] Current Users Container: $($Domain.UsersContainer)" -ForegroundColor Gray
    if ($Domain.UsersContainer -eq $DefaultUsersDN) {
        Write-Host "VULNERABLE: Default Users container is NOT redirected." -ForegroundColor Red
        $Compliant = $false
    } else {
        # Verify the redirected container is an OU and is protected from deletion
        $UserOU = Get-ADOrganizationalUnit -Identity $Domain.UsersContainer -Properties ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue
        if ($UserOU) {
            if ($UserOU.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Users Container redirected to a protected OU (Compliant)." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Users Container redirected to OU '$($UserOU.Name)' but Accidental Deletion Protection is DISABLED." -ForegroundColor Red
                $Compliant = $false
            }
        } else {
            Write-Host "VULNERABLE: Users Container is redirected to a non-OU object or the target container does not exist." -ForegroundColor Red
            $Compliant = $false
        }
    }
    
    if ($Compliant) {
        Write-Host "`nStatus: Compliant. User and Computer default containers are redirected to deletion-protected OUs." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`nStatus: Non-Compliant. Default containers redirection needs to be configured or corrected." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "VULNERABLE: Could not query Active Directory Domain settings. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
```

#### 2. Local Remediation

[Download Script: Set-DefaultContainersRedirection.ps1](implementation_scripts/Set-DefaultContainersRedirection.ps1)

```powershell
# Set-DefaultContainersRedirection.ps1
# Description: Creates new OUs, protects them from accidental deletion, and redirects default users/computers containers.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Redirect Default Containers to Protected OUs..." -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName
    $TargetComputersOU = "OU=New-Computers,$($DomainDN)"
    $TargetUsersOU = "OU=New-Users,$($DomainDN)"
    
    # 1. Create and protect target Computers OU
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetComputersOU'")) {
        Write-Host "[+] Creating target Computers OU: New-Computers" -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "New-Computers" -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Computers OU created and protected successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Target Computers OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        Set-ADOrganizationalUnit -Identity $TargetComputersOU -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Accidental deletion protection verified on target Computers OU." -ForegroundColor Green
    }
    
    # 2. Create and protect target Users OU
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetUsersOU'")) {
        Write-Host "[+] Creating target Users OU: New-Users" -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "New-Users" -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Users OU created and protected successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Target Users OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        Set-ADOrganizationalUnit -Identity $TargetUsersOU -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Accidental deletion protection verified on target Users OU." -ForegroundColor Green
    }
    
    # 3. Perform Computers Redirection
    if ($Domain.ComputersContainer -ne $TargetComputersOU) {
        Write-Host "[+] Redirecting default Computers container to $TargetComputersOU..." -ForegroundColor Yellow
        $Output = & redircmp.exe $TargetComputersOU 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Computers container redirected successfully." -ForegroundColor Green
        } else {
            throw "Failed to redirect Computers container: $($Output)"
        }
    } else {
        Write-Host "[+] Computers container is already redirected to target OU." -ForegroundColor Green
    }
    
    # 4. Perform Users Redirection
    if ($Domain.UsersContainer -ne $TargetUsersOU) {
        Write-Host "[+] Redirecting default Users container to $TargetUsersOU..." -ForegroundColor Yellow
        $Output = & redirusr.exe $TargetUsersOU 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Users container redirected successfully." -ForegroundColor Green
        } else {
            throw "Failed to redirect Users container: $($Output)"
        }
    } else {
        Write-Host "[+] Users container is already redirected to target OU." -ForegroundColor Green
    }
    
    Write-Host "`n[+] Redirection operations completed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply redirection. Error: $($_.Exception.Message)"
    exit 1
}
```

---

## Sources & Compliance References
* **Microsoft Technical Reference**: [Redirecting Users and Computers Containers in Active Directory Domains](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers)
* **ANSSI AD Hardening Guide**: Section on Active Directory structure and logical partitioning.
