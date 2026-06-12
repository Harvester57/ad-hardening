# Hardening Requirement: Implement Group Managed Service Accounts (gMSA)

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
    # Specify the name, DNS, and which principals (servers/DCs) can retrieve the password
    New-ADServiceAccount -Name $gMSAName `
        -DNSHostName "$gMSAName.domain.local" `
        -ManagedPasswordIntervalInDays 30 `
        -PrincipalsAllowedToRetrieveManagedPassword "Domain Controllers", "Schema Admins"
        
    Write-Host "[+] gMSA '$gMSAName' created successfully." -ForegroundColor Green
} else {
    Write-Host "[-] gMSA '$gMSAName' already exists." -ForegroundColor Yellow
}
```

*To audit registered Managed Service Accounts:*
[Download Script: Get-gMSAStatus.ps1](audit_scripts/Get-gMSAStatus.ps1)

```powershell
# Get-gMSAStatus.ps1
# Description: Lists all registered gMSAs and their configuration details.

Import-Module ActiveDirectory

Write-Host "--- Auditing Group Managed Service Accounts ---" -ForegroundColor Cyan

$gMSAs = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, PrincipalsAllowedToRetrieveManagedPassword

if ($gMSAs) {
    foreach ($sa in $gMSAs) {
        Write-Host "[+] gMSA Account: $($sa.Name)" -ForegroundColor Green
        Write-Host "    - DNS Name: $($sa.DNSHostName)" -ForegroundColor White
        Write-Host "    - Enabled: $($sa.Enabled)" -ForegroundColor White
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
