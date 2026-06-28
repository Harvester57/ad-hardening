# Get-ExchangePermissionsStatus.ps1
# Check if Exchange groups hold WriteDacl/WriteOwner permissions on the domain root.

Import-Module ActiveDirectory

$DomainDN = (Get-ADDomain).DistinguishedName
$DomainPath = "AD:\$DomainDN"

$Acl = Get-Acl -Path $DomainPath
$TargetGroups = @("Exchange Windows Permissions", "Exchange Servers")
$TargetSids = @()

foreach ($groupName in $TargetGroups) {
    try {
        $sid = (Get-ADGroup -Identity $groupName).SID.Value
        $TargetSids += $sid
    }
    catch {
        # Group not present in domain
    }
}

if ($TargetSids.Count -eq 0) {
    Write-Host "[+] COMPLIANT: Exchange groups are not present in this domain."
    exit 0
}

$nonCompliantAces = 0

foreach ($ace in $Acl.Access) {
    $identity = $ace.IdentityReference
    try {
        $sid = $identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        continue
    }

    if ($TargetSids -contains $sid) {
        $hasWriteDacl = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $hasWriteOwner = ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

        if ($hasWriteDacl -or $hasWriteOwner) {
            Write-Host "[!] NON-COMPLIANT: Group '$($identity.Value)' has permissions: $($ace.ActiveDirectoryRights)" -ForegroundColor Red
            $nonCompliantAces++
        }
    }
}

if ($nonCompliantAces -eq 0) {
    Write-Host "[+] COMPLIANT: No Exchange groups have WriteDacl or WriteOwner permissions on the domain root." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[!] NON-COMPLIANT: Dangerous Exchange write permissions detected on the domain root." -ForegroundColor Red
    exit 1
}
