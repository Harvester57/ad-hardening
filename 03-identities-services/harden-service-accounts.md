# [REQ-ID-003] Implement Group Managed Service Accounts (gMSA)

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Active Directory Object Management (Managed Service Accounts container: `CN=Managed Service Accounts,DC=[Domain]`)

---

## Rationale
Traditional service accounts in Active Directory are standard user accounts with static, often long-lived passwords. Because service passwords are rarely rotated, they are prime targets for offline brute-force attacks known as **Kerberoasting**. An attacker with domain access can request a Kerberos service ticket (TGS) for any account with a Service Principal Name (SPN) and attempt to crack the password hash offline.

Group Managed Service Accounts (gMSAs) address this risk by delegating password management to the operating system and Domain Controllers. Windows automatically generates a complex 120-character password for each gMSA and rotates it every 30 days. Additionally, gMSAs cannot be used for interactive logons, preventing administrative session hijacking or remote administrative access via service accounts.

However, gMSAs introduce specific security boundaries that must be strictly enforced:
1. **Password Retrieval Delegation (GMSA Password Access)**: The attribute `msDS-GroupMSAMembership` (`PrincipalsAllowedToRetrieveManagedPassword`) defines which security principals can query Active Directory to retrieve the clear-text gMSA password. If human user accounts or groups containing human users are added to this attribute, any compromise of those user credentials allows an attacker to fetch the clear-text password blob and convert it to an NT hash.
2. **Credential Dumping from memory (LSASS ekeys)**: While LSASS does not cache the clear-text password of a gMSA under standard `sekurlsa::logonpasswords` dumps, the active Kerberos keys (NT hash, AES-128/256 keys) are stored in memory on the host computer running the service. An attacker with administrative/SYSTEM access to the host server can extract these keys using Mimikatz `sekurlsa::ekeys` and use them for pass-the-hash (PTH) or pass-the-ticket (PTT) attacks.
3. **Tier Alignment (Tier-Matching)**: Because compromising the host server hosting a gMSA compromises the gMSA itself, and retrieving the gMSA password grants full control over its permissions, hosts running gMSAs must be secured to the same level (Tier) as the privileges granted to the gMSA. A Tier 0 gMSA must only run on Tier 0 systems (Domain Controllers or Tier 0 Admin Hosts), and only Tier 0 computer accounts/groups must be allowed to retrieve its password.

---

## Legacy Impact & Compatibility
* **OS Compatibility**: gMSAs require a domain functional level of Windows Server 2012 or higher. Client hosts running the service must run Windows Server 2012/Windows 8 or higher.
* **Application Support**: While major enterprise services such as Microsoft SQL Server, IIS, and Windows Services support gMSAs native, some legacy third-party applications do not support managing authentication without standard credentials.
* **Active Directory KDS Root Key**: A Key Distribution Service (KDS) Root Key must be generated once in the forest before any gMSA can be created.

---

## Implementation Steps

### Option A: Active Directory Management Console Configuration (Preferred)

gMSAs are primarily created and managed using administrative consoles or PowerShell.

1. Open **Active Directory Users and Computers** (`dsa.msc`).
2. Verify the presence of the default **Managed Service Accounts** container.
3. Because gMSA creation requires AD schema and principal mapping, PowerShell is the primary method used to initialize and link the account to the host server. Follow the steps in Option B.
4. Once created, configure the target service (e.g., in Services Console `services.msc`):
   * Set **Log On As** to **This account**.
   * Enter the name of the gMSA with a trailing dollar sign (e.g., `domain\gmsa-sqlservice$`).
   * Clear the Password fields and click **OK**.
   * Restart the service.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use the following PowerShell script to initialize the KDS root key (if not already done) and create a gMSA.

[Download Script: Set-gMSAServiceAccount.ps1](implementation_scripts/Set-gMSAServiceAccount.ps1)

```powershell
# Set-gMSAServiceAccount.ps1
# Description: Generates the KDS root key and registers a new gMSA.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Implement Group Managed Service Accounts..." -ForegroundColor Cyan

# 1. Initialize KDS Root Key (Required once in the forest)
# In standard setups, there is a 10-hour delay for propagation.
# -EffectiveImmediately is used for lab configurations.
try {
    Add-KdsRootKey -EffectiveImmediately -ErrorAction SilentlyContinue
    Write-Host "[+] KDS Root Key creation initiated/verified." -ForegroundColor Green
} catch {
    Write-Warning "Could not configure KDS Root Key. It may already exist."
}

# 2. Create the gMSA
$gMSAName = "gmsa-sqlservice"
$existingMSA = Get-ADServiceAccount -Filter "Name -eq '$gMSAName'"

if (-not $existingMSA) {
    # Specify the name, DNS, and which principals (member servers running the service) can retrieve the password.
    # CRITICAL: Do NOT allow user accounts or groups containing users (like Domain Admins or Schema Admins) 
    # to retrieve the password. Only allow the specific computer account(s) hosting the service.
    $targetHostComputer = "SQLServerHost$"
    
    New-ADServiceAccount -Name $gMSAName `
        -DNSHostName "$gMSAName.domain.local" `
        -ManagedPasswordIntervalInDays 30 `
        -PrincipalsAllowedToRetrieveManagedPassword $targetHostComputer
        
    Write-Host "[+] gMSA '$gMSAName' created successfully." -ForegroundColor Green
} else {
    Write-Host "[-] gMSA '$gMSAName' already exists." -ForegroundColor Yellow
}
```

*To audit registered Managed Service Accounts:*
[Download Script: Get-gMSAStatus.ps1](audit_scripts/Get-gMSAStatus.ps1)


```powershell
# Get-gMSAStatus.ps1
# Description: Lists all registered gMSAs and audits password retrieval delegation permissions.

Import-Module ActiveDirectory

Write-Host "--- Auditing Group Managed Service Accounts ---" -ForegroundColor Cyan

$gMSAs = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, PrincipalsAllowedToRetrieveManagedPassword

if ($gMSAs) {
    foreach ($sa in $gMSAs) {
        $nonCompliant = $false
        Write-Host "[*] gMSA Account: $($sa.Name)" -ForegroundColor White
        Write-Host "    - DNS Name: $($sa.DNSHostName)" -ForegroundColor White
        Write-Host "    - Enabled: $($sa.Enabled)" -ForegroundColor White
        
        $principals = $sa.PrincipalsAllowedToRetrieveManagedPassword
        if ($null -ne $principals) {
            Write-Host "    - Principals Allowed to Retrieve Password:" -ForegroundColor White
            foreach ($p in $principals) {
                # Get the AD Object to verify class and name
                $adObj = Get-ADObject -Identity $p.DistinguishedName -Properties ObjectClass, Name
                if ($null -ne $adObj) {
                    $objType = $adObj.ObjectClass
                    $name = $adObj.Name
                    
                    if ($objType -eq "user") {
                        Write-Host "      [-] WARNING: User account '$($name)' is explicitly allowed to retrieve password (HIGH RISK)" -ForegroundColor Red
                        $nonCompliant = $true
                    } elseif ($objType -eq "group") {
                        Write-Host "      [!] Group: '$($name)'" -ForegroundColor Yellow
                        
                        # Recursively resolve members to check for users
                        $members = Get-ADGroupMember -Identity $p.DistinguishedName -Recursive
                        $userMembers = $members | Where-Object { $_.objectClass -eq "user" }
                        
                        if ($userMembers) {
                            $userNames = @()
                            foreach ($user in $userMembers) {
                                $userNames += $user.Name
                            }
                            $usersList = $userNames -join ", "
                            Write-Host "        [-] WARNING: Group '$($name)' contains human user accounts: $($usersList) (HIGH RISK)" -ForegroundColor Red
                            $nonCompliant = $true
                        } else {
                            Write-Host "        [+] Group contains only computer/service accounts." -ForegroundColor Green
                        }
                    } else {
                        Write-Host "      [+] Computer/Host: '$($name)'" -ForegroundColor Green
                    }
                }
            }
        } else {
            Write-Host "    [-] WARNING: No principals allowed to retrieve password (gMSA will not function)." -ForegroundColor Yellow
            $nonCompliant = $true
        }
        
        if ($nonCompliant) {
            Write-Host "    [-] STATUS: NON-COMPLIANT (Insecure password retrieval delegation)" -ForegroundColor Red
        } else {
            Write-Host "    [+] STATUS: COMPLIANT" -ForegroundColor Green
        }
        Write-Host ""
    }
} else {
    Write-Host "[-] No Group Managed Service Accounts found in the Active Directory domain." -ForegroundColor Yellow
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Section on Service account authentication management
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section on Managed Service Accounts
* **Microsoft Security Guidance**: Group Managed Service Accounts Overview
* **Trimarc ADSecurity**: [Attacking Active Directory Group Managed Service Accounts (GMSAs)](https://adsecurity.org/?p=4367)

