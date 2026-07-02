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
