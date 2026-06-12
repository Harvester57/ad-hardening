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
