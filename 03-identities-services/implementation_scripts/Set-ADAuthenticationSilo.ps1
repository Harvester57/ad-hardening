# Set-ADAuthenticationSilo.ps1
# Description: Configures Active Directory Authentication Policies and Silos for Tier 0 isolation.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [switch]$Enforce,

    [Parameter(Mandatory = $false)]
    [string]$PolicyName = "T0_AuthPol",

    [Parameter(Mandatory = $false)]
    [string]$SiloName = "T0_Silo",

    [Parameter(Mandatory = $false)]
    [string]$UserGroupName = "Grp_Tier0_Admins",

    [Parameter(Mandatory = $false)]
    [string]$ComputerGroupName = "Grp_Tier0_PAWs",

    [Parameter(Mandatory = $false)]
    [int]$UserTGTLifetimeMins = 120
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Applying hardening requirement: Configure Active Directory Authentication Silos..." -ForegroundColor Cyan

# 1. Validate Domain Functional Level
$domain = Get-ADDomain -ErrorAction Stop
if ($domain.DomainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2012R2Domain) {
    Write-Error "Active Directory Domain Functional Level must be Windows Server 2012 R2 or higher. Current DFL: $($domain.DomainMode)"
    return
}

# 2. Configure KDC and Kerberos Client Registry Keys on Local Domain Controller
$kdcRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"
$kerbRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path -Path $kdcRegPath)) {
    New-Item -Path $kdcRegPath -Force | Out-Null
}
# Enable KDC support for claims, compound authentication, and armoring (1 = Supported)
Set-ItemProperty -Path $kdcRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $kdcRegPath -Name "CbacAndArmorLevel" -Value 1 -Type DWord -Force
Write-Host "[+] Local KDC registry configured for claims and Kerberos armoring." -ForegroundColor Green

if (-not (Test-Path -Path $kerbRegPath)) {
    New-Item -Path $kerbRegPath -Force | Out-Null
}
Set-ItemProperty -Path $kerbRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord -Force
Write-Host "[+] Local Kerberos client registry configured for claims and armoring." -ForegroundColor Green

# 3. Enable Operational Event Log Channel on Domain Controller
try {
    $logChannel = "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController/Operational"
    wevtutil sl $logChannel /e:true 2>$null
    Write-Host "[+] Enabled operational log channel: $($logChannel)" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not configure operational log channel via wevtutil: $($_.Exception.Message)" -ForegroundColor Yellow
}

$enforceMode = $Enforce.IsPresent
$modeDescription = if ($enforceMode) { "Enforced" } else { "Audit Mode (Staging)" }
Write-Host "[*] Configuring Authentication Silo and Policy in mode: $($modeDescription)" -ForegroundColor Cyan

# 4. Construct Device Claims SDDL Condition
# Limits user authentication exclusively to devices belonging to the specified Silo
$deviceConditionSddl = "O:SYG:SYD:(XA;;CR;;;WD;(@Device.ad:silo == `"$SiloName`"))"

# 5. Create or Update the Authentication Policy
$existPolicy = Get-ADAuthenticationPolicy -Filter "Name -eq '$PolicyName'" -ErrorAction SilentlyContinue

if (-not $existPolicy) {
    New-ADAuthenticationPolicy -Name $PolicyName `
        -Description "Authentication Policy for Tier 0 Isolation" `
        -UserTGTLifetimeMins $UserTGTLifetimeMins `
        -UserAllowedToAuthenticateFrom $deviceConditionSddl `
        -Enforce $enforceMode `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy '$PolicyName' created (Enforce: $($enforceMode), TGT Lifetime: $($UserTGTLifetimeMins)m)." -ForegroundColor Green
} else {
    Set-ADAuthenticationPolicy -Identity $PolicyName `
        -UserTGTLifetimeMins $UserTGTLifetimeMins `
        -UserAllowedToAuthenticateFrom $deviceConditionSddl `
        -Enforce $enforceMode `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy '$PolicyName' updated (Enforce: $($enforceMode), TGT Lifetime: $($UserTGTLifetimeMins)m)." -ForegroundColor Green
}

# 6. Create or Update the Authentication Policy Silo
$existSilo = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$SiloName'" -ErrorAction SilentlyContinue

if (-not $existSilo) {
    New-ADAuthenticationPolicySilo -Name $SiloName `
        -Description "Authentication Policy Silo for Tier 0 Containment" `
        -UserAuthenticationPolicy $PolicyName `
        -ComputerAuthenticationPolicy $PolicyName `
        -ServiceAuthenticationPolicy $PolicyName `
        -Enforce $enforceMode `
        -ProtectedFromAccidentalDeletion $true `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy Silo '$SiloName' created (Enforce: $($enforceMode))." -ForegroundColor Green
} else {
    Set-ADAuthenticationPolicySilo -Identity $SiloName `
        -UserAuthenticationPolicy $PolicyName `
        -ComputerAuthenticationPolicy $PolicyName `
        -ServiceAuthenticationPolicy $PolicyName `
        -Enforce $enforceMode `
        -ErrorAction Stop
    Write-Host "[+] Authentication Policy Silo '$SiloName' updated (Enforce: $($enforceMode))." -ForegroundColor Green
}

# 7. Grant Silo Access and Enroll Domain Controllers (Mandatory for T0 Silo)
Write-Host "[*] Enrolling Domain Controllers into silo '$SiloName'..." -ForegroundColor White
$domainControllers = Get-ADDomainController -Filter "IsReadOnly -eq `$false"
foreach ($dc in $domainControllers) {
    $dcDn = $dc.ComputerObjectDN
    Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $dcDn -ErrorAction SilentlyContinue
    Set-ADAccountAuthenticationPolicySilo -Identity $dcDn -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
    Write-Host "    - Enrolled DC: $($dc.HostName)" -ForegroundColor Gray
}

# 8. Grant Silo Access and Enroll Tier 0 Admin Users
$userGroup = Get-ADGroup -Filter "Name -eq '$UserGroupName'" -ErrorAction SilentlyContinue
if ($userGroup) {
    Write-Host "[*] Enrolling members of user group '$UserGroupName'..." -ForegroundColor White
    $adminUsers = Get-ADGroupMember -Identity $userGroup -Recursive | Where-Object { $_.objectClass -eq "user" }
    foreach ($user in $adminUsers) {
        Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $user.distinguishedName -ErrorAction SilentlyContinue
        Set-ADAccountAuthenticationPolicySilo -Identity $user.distinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
        Write-Host "    - Enrolled User: $($user.SamAccountName)" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] User group '$UserGroupName' not found in Active Directory. Skipping user enrollment." -ForegroundColor Yellow
}

# 9. Grant Silo Access and Enroll Tier 0 PAW Computers
$compGroup = Get-ADGroup -Filter "Name -eq '$ComputerGroupName'" -ErrorAction SilentlyContinue
if ($compGroup) {
    Write-Host "[*] Enrolling members of computer group '$ComputerGroupName'..." -ForegroundColor White
    $pawComputers = Get-ADGroupMember -Identity $compGroup -Recursive | Where-Object { $_.objectClass -eq "computer" }
    foreach ($comp in $pawComputers) {
        Grant-ADAuthenticationPolicySiloAccess -Identity $SiloName -Account $comp.distinguishedName -ErrorAction SilentlyContinue
        Set-ADAccountAuthenticationPolicySilo -Identity $comp.distinguishedName -AuthenticationPolicySilo $SiloName -ErrorAction SilentlyContinue
        Write-Host "    - Enrolled Computer: $($comp.SamAccountName)" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] Computer group '$ComputerGroupName' not found in Active Directory. Skipping computer enrollment." -ForegroundColor Yellow
}

# 10. Audit Protected Users Group Membership for Silo Users
Write-Host "[*] Auditing Protected Users membership for Tier 0 silo accounts..." -ForegroundColor White
$protectedUsersGroup = Get-ADGroup -Identity "Protected Users" -ErrorAction SilentlyContinue
if ($protectedUsersGroup) {
    $siloMembers = Get-ADAuthenticationPolicySilo -Identity $SiloName -Properties Members
    $unprotectedCount = 0
    foreach ($memberDn in $siloMembers.Members) {
        $accountObj = Get-ADObject -Identity $memberDn -Properties objectClass, sAMAccountName -ErrorAction SilentlyContinue
        if ($accountObj -and $accountObj.objectClass -eq "user") {
            $isProtected = Get-ADGroupMember -Identity "Protected Users" -Recursive | Where-Object { $_.distinguishedName -eq $memberDn }
            if (-not $isProtected) {
                Write-Host "[!] WARNING: Silo user '$($accountObj.sAMAccountName)' is NOT in Protected Users group! Vulnerable to NTLM bypass." -ForegroundColor Yellow
                $unprotectedCount++
            }
        }
    }
    if ($unprotectedCount -eq 0) {
        Write-Host "[+] All enrolled silo users are members of the Protected Users group." -ForegroundColor Green
    }
}

Write-Host "[+] Authentication Silo membership initialized." -ForegroundColor Green
