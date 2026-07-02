# Harden-AdminSDHolder.ps1
# Description: Hardens the adminSDHolder ACL by auditing permissions, blocking inheritance, and removing delegated helpdesk groups.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Harden adminSDHolder Permissions..." -ForegroundColor Cyan

# Set target DN
$DomainDN = (Get-ADRootDSE).defaultNamingContext
$AdminSDPath = "AD:\CN=adminSDHolder,CN=System,$($DomainDN)"

# Define allowed high-privilege built-in identities (SIDs or names)
$AllowedTrustees = @(
    "SYSTEM",
    "Domain Admins",
    "Enterprise Admins",
    "Administrators"
)

# Fetch ACL
$Acl = Get-Acl -Path $AdminSDPath
$AclModified = $false

# 1. Enforce inheritance blocking (DACL_Protected flag)
if ($Acl.AreAccessRulesProtected) {
    Write-Host "[+] Inheritance is already blocked (protected) on the adminSDHolder container." -ForegroundColor Green
} else {
    Write-Host "[-] adminSDHolder container has inheritance enabled. Blocking inheritance..." -ForegroundColor Yellow
    # Block inheritance ($true) and copy existing rules as explicit ($true)
    $Acl.SetAccessRuleProtection($true, $true)
    $AclModified = $true
}

# 2. Prune non-compliant permissions
foreach ($Rule in $Acl.Access) {
    $Identity = $Rule.IdentityReference.Value
    
    # Check if trustee is allowed to write
    if ($Rule.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner|GenericAll|GenericWrite") {
        $IsAllowed = $false
        foreach ($Allowed in $AllowedTrustees) {
            if ($Identity -match $Allowed) {
                $IsAllowed = $true
                break
            }
        }
        
        if (-not $IsAllowed) {
            Write-Host "[-] Unauthorized write permission found: Account '$($Identity)' has rights: $($Rule.ActiveDirectoryRights)" -ForegroundColor Yellow
            
            # Remove rule
            $Acl.RemoveAccessRule($Rule) | Out-Null
            $AclModified = $true
        }
    }
}

if ($AclModified) {
    Set-Acl -Path $AdminSDPath -AclObject $Acl -ErrorAction Stop
    Write-Host "[+] adminSDHolder ACL hardened successfully." -ForegroundColor Green
} else {
    Write-Host "[+] adminSDHolder ACL is already clean." -ForegroundColor Green
}
