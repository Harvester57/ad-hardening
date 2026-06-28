# Harden-ExchangePermissions.ps1
# Description: Removes WriteDacl and WriteOwner permissions for Exchange groups on the domain root.

Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainPath = "AD:\$DomainDN"

# Retrieve existing ACL
$Acl = Get-Acl -Path $DomainPath
$DangerousAcesToRemove = @()

# Define Exchange groups to target
$TargetGroups = @("Exchange Windows Permissions", "Exchange Servers")
$TargetSids = @()

foreach ($groupName in $TargetGroups) {
    try {
        $sid = (Get-ADGroup -Identity $groupName).SID.Value
        $TargetSids += $sid
    }
    catch {
        Write-Host "Group '$groupName' not found in this domain. Skipping." -ForegroundColor Yellow
    }
}

if ($TargetSids.Count -eq- 0) {
    Write-Host "No Exchange groups detected. No permissions to harden." -ForegroundColor Green
    exit 0
}

# Scan ACL for dangerous ACEs
foreach ($ace in $Acl.Access) {
    $identity = $ace.IdentityReference
    try {
        $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        continue
    }

    if ($TargetSids -contains $sid) {
        # Check for WriteDacl or WriteOwner rights
        $hasWriteDacl = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $hasWriteOwner = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        if ($hasWriteDacl -or $hasWriteOwner) {
            $DangerousAcesToRemove += $ace
        }
    }
}

if ($DangerousAcesToRemove.Count -eq 0) {
    Write-Host "[+] Domain root ACL is compliant. No dangerous Exchange write permissions found." -ForegroundColor Green
} else {
    Write-Host "[-] Found $($DangerousAcesToRemove.Count) dangerous Exchange permissions. Removing..." -ForegroundColor Yellow
    foreach ($ace in $DangerousAcesToRemove) {
        $Acl.RemoveAccessRule($ace) | Out-Null
    }
    Set-Acl -Path $DomainPath -AclObject $Acl
    Write-Host "[+] Successfully removed dangerous Exchange WriteDacl/WriteOwner permissions from domain root." -ForegroundColor Green
}
