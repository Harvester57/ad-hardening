# Get-dSHeuristicsStatus.ps1
# Description: Audits the dSHeuristics attribute settings for security compliance.

Write-Host "--- Auditing dSHeuristics Configuration ---" -ForegroundColor Cyan

$rootDSE = [ADSI]"LDAP://RootDSE"
$configNamingContext = $rootDSE.configurationNamingContext[0]
$dsPath = "LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNamingContext"

$dsObject = [ADSI]$dsPath
$dsHeuristics = $dsObject.Properties["dSHeuristics"].Value

function Get-HeuristicChar {
    param(
        [string]$String,
        [int]$Index, # 0-based index
        [char]$Default = [char]"0"
    )
    if ($null -ne $String -and $String.Length -gt $Index) {
        return $String.Substring($Index, 1)
    }
    return $Default
}

$vulnerable = $false
$nonLevel5 = $false

if ($null -eq $dsHeuristics -or $dsHeuristics -eq "") {
    Write-Host "[!] dSHeuristics is not set. Default settings apply." -ForegroundColor Yellow
    Write-Host "    - AttributeAuthorizationOnLDAPAdd: Not Set (defaults to 0, which is Level 3/4 but NOT Level 5)" -ForegroundColor Yellow
    Write-Host "    - BlockOwnerImplicitRights: Not Set (defaults to 0, which is Level 3/4 but NOT Level 5)" -ForegroundColor Yellow
    $nonLevel5 = $true
} else {
    Write-Host "[+] Current dSHeuristics string: $dsHeuristics" -ForegroundColor Green
    
    # 7. fLDAPBlockAnonOps (Index 6)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 6
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: fLDAPBlockAnonOps is set to '2' (Allows anonymous LDAP operations)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] fLDAPBlockAnonOps (Index 6): Set to '$val' (Anonymous LDAP operations blocked)." -ForegroundColor Green
    }
    
    # 8. fAllowAnonNSPI (Index 7)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 7
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: fAllowAnonNSPI is set to '$val' (Allows anonymous NSPI access; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] fAllowAnonNSPI (Index 7): Set to '0' (Anonymous NSPI blocked)." -ForegroundColor Green
    }
    
    # 16. dwAdminSDExMask (Index 15)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 15
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: dwAdminSDExMask is set to '$val' (Disables protection for administrative groups; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] dwAdminSDExMask (Index 15): Set to '0' (All default admin groups protected)." -ForegroundColor Green
    }
    
    # 21. DoNotVerifyUPNAndOrSPNUniqueness (Index 20)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 20
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: DoNotVerifyUPNAndOrSPNUniqueness is set to '$val' (Bypasses UPN/SPN uniqueness checks; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] DoNotVerifyUPNAndOrSPNUniqueness (Index 20): Set to '0' (Uniqueness checks active)." -ForegroundColor Green
    }
    
    # 28. AttributeAuthorizationOnLDAPAdd (Index 27)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 27
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: AttributeAuthorizationOnLDAPAdd is set to '2' (Bypasses LDAP Add authorization checks)." -ForegroundColor Red
        $vulnerable = $true
    } elseif ($val -ne "1") {
        Write-Host "[!] WARNING: AttributeAuthorizationOnLDAPAdd is set to '$val' (Must be set to '1' for Level 5 security)." -ForegroundColor Yellow
        $nonLevel5 = $true
    } else {
        Write-Host "[+] AttributeAuthorizationOnLDAPAdd (Index 27): Set to '1' (Level 5 secure)." -ForegroundColor Green
    }
    
    # 29. BlockOwnerImplicitRights (Index 28)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 28
    if ($val -eq "2") {
        Write-Host "[!] VULNERABLE: BlockOwnerImplicitRights is set to '2' (Bypasses owner implicit rights protection)." -ForegroundColor Red
        $vulnerable = $true
    } elseif ($val -ne "1") {
        Write-Host "[!] WARNING: BlockOwnerImplicitRights is set to '$val' (Must be set to '1' for Level 5 security)." -ForegroundColor Yellow
        $nonLevel5 = $true
    } else {
        Write-Host "[+] BlockOwnerImplicitRights (Index 28): Set to '1' (Level 5 secure)." -ForegroundColor Green
    }
    
    # 31. DisableConfidentialAttributeEncryptionRequirements (Index 30)
    $val = Get-HeuristicChar -String $dsHeuristics -Index 30
    if ($val -ne "0") {
        Write-Host "[!] VULNERABLE: DisableConfidentialAttributeEncryptionRequirements is set to '$val' (Allows unencrypted transmission of confidential attributes; must be 0)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] DisableConfidentialAttributeEncryptionRequirements (Index 30): Set to '0' (Requires encrypted connection)." -ForegroundColor Green
    }
}

if ($vulnerable) {
    Write-Host "[!] Result: VULNERABLE (Dangerous settings detected in dSHeuristics)." -ForegroundColor Red
} elseif ($nonLevel5) {
    Write-Host "[!] Result: Partially Secure (No highly dangerous settings, but Level 5 maximum security is not reached)." -ForegroundColor Yellow
} else {
    Write-Host "[+] Result: SECURE (Level 5 security reached)." -ForegroundColor Green
}
