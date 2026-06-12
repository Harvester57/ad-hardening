# Set-ADModularGPO.ps1
# Description: Creates a new, dedicated Domain Controllers hardening GPO and links it with top precedence.

Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "Applying hardening requirement: Create and link DC Hardening GPO..." -ForegroundColor Cyan

$DomainInfo = Get-ADDomain
$DCOUDN = "OU=Domain Controllers,$($DomainInfo.DistinguishedName)"
$GPOName = "SEC_DomainControllers_Hardening"

try {
    # 1. Create the GPO if it doesn't exist
    $GPO = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if (-not $GPO) {
        $GPO = New-GPO -Name $GPOName -Comment "Dedicated GPO for Domain Controllers hardening settings." -ErrorAction Stop
        Write-Host "[+] GPO '$GPOName' created successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' already exists." -ForegroundColor Yellow
    }
    
    # 2. Link the GPO to Domain Controllers OU
    $Links = (Get-GPInheritance -Target $DCOUDN).GpoLinks
    $IsLinked = $false
    foreach ($link in $Links) {
        if ($link.DisplayName -eq $GPOName) {
            $IsLinked = $true
            break
        }
    }
    
    if (-not $IsLinked) {
        New-GPLink -Name $GPOName -Target $DCOUDN -LinkEnabled Yes -ErrorAction Stop | Out-Null
        Write-Host "[+] GPO '$GPOName' linked to Domain Controllers OU." -ForegroundColor Green
    } else {
        Write-Host "[+] GPO '$GPOName' is already linked to Domain Controllers OU." -ForegroundColor Yellow
    }
    
    # 3. Enforce highest precedence (Link Order = 1)
    Set-GPLink -Name $GPOName -Target $DCOUDN -Order 1 -ErrorAction Stop | Out-Null
    Write-Host "[+] GPO '$GPOName' set to link order 1 (highest precedence)." -ForegroundColor Green
    
} catch {
    Write-Error "Failed to configure GPO. Error: $($_.Exception.Message)"
}
