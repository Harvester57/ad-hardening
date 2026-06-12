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
