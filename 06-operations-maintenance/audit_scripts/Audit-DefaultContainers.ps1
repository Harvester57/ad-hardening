# Audit-DefaultContainers.ps1
# Description: Audits if the default user and computer containers have been redirected to protected OUs.

Import-Module ActiveDirectory

Write-Host "--- Auditing Default User and Computer Containers Redirection ---" -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName
    $DefaultComputersDN = "CN=Computers,$($DomainDN)"
    $DefaultUsersDN = "CN=Users,$($DomainDN)"
    
    $Compliant = $true
    
    # 1. Check Computers Container
    Write-Host "[+] Current Computers Container: $($Domain.ComputersContainer)" -ForegroundColor Gray
    if ($Domain.ComputersContainer -eq $DefaultComputersDN) {
        Write-Host "VULNERABLE: Default Computers container is NOT redirected." -ForegroundColor Red
        $Compliant = $false
    } else {
        # Verify the redirected container is an OU and is protected from deletion
        $CompOU = Get-ADOrganizationalUnit -Identity $Domain.ComputersContainer -Properties ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue
        if ($CompOU) {
            if ($CompOU.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Computers Container redirected to a protected OU (Compliant)." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Computers Container redirected to OU '$($CompOU.Name)' but Accidental Deletion Protection is DISABLED." -ForegroundColor Red
                $Compliant = $false
            }
        } else {
            Write-Host "VULNERABLE: Computers Container is redirected to a non-OU object or the target container does not exist." -ForegroundColor Red
            $Compliant = $false
        }
    }
    
    # 2. Check Users Container
    Write-Host "[+] Current Users Container: $($Domain.UsersContainer)" -ForegroundColor Gray
    if ($Domain.UsersContainer -eq $DefaultUsersDN) {
        Write-Host "VULNERABLE: Default Users container is NOT redirected." -ForegroundColor Red
        $Compliant = $false
    } else {
        # Verify the redirected container is an OU and is protected from deletion
        $UserOU = Get-ADOrganizationalUnit -Identity $Domain.UsersContainer -Properties ProtectedFromAccidentalDeletion -ErrorAction SilentlyContinue
        if ($UserOU) {
            if ($UserOU.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Users Container redirected to a protected OU (Compliant)." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Users Container redirected to OU '$($UserOU.Name)' but Accidental Deletion Protection is DISABLED." -ForegroundColor Red
                $Compliant = $false
            }
        } else {
            Write-Host "VULNERABLE: Users Container is redirected to a non-OU object or the target container does not exist." -ForegroundColor Red
            $Compliant = $false
        }
    }
    
    if ($Compliant) {
        Write-Host "`nStatus: Compliant. User and Computer default containers are redirected to deletion-protected OUs." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`nStatus: Non-Compliant. Default containers redirection needs to be configured or corrected." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "VULNERABLE: Could not query Active Directory Domain settings. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
