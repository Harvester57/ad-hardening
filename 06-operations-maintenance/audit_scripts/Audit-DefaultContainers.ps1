# Audit-DefaultContainers.ps1
# Description: Audits Active Directory default user and computer container redirection,
#              verifies accidental deletion protection, checks GPO linkage, and inventories residual accounts.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Active Directory Default Containers Redirection ---" -ForegroundColor Cyan

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "VULNERABLE: The ActiveDirectory PowerShell module is not installed or available on this system." -ForegroundColor Red
    exit 1
}

Import-Module ActiveDirectory

$isVulnerable = $false

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName
    $defaultComputersDN = "CN=Computers,$($domainDN)"
    $defaultUsersDN = "CN=Users,$($domainDN)"

    Write-Host "[i] Domain Distinguished Name: $($domainDN)" -ForegroundColor Gray
    Write-Host "[i] Domain Functional Level : $($domain.DomainMode)" -ForegroundColor Gray
    Write-Host ""

    # -------------------------------------------------------------
    # 2. Check Computers Container Redirection
    # -------------------------------------------------------------
    Write-Host "Checking Computers Container Configuration..." -ForegroundColor Yellow
    $currentCompContainer = $domain.ComputersContainer
    Write-Host "[i] Current Computers Container: $($currentCompContainer)" -ForegroundColor Gray

    if ($currentCompContainer -eq $defaultComputersDN) {
        Write-Host "VULNERABLE: Default Computers container is NOT redirected. Newly joined computers land in unmanaged 'CN=Computers'." -ForegroundColor Red
        $isVulnerable = $true
    } else {
        # Verify the redirected container is an OU
        $compTarget = Get-ADObject -Identity $currentCompContainer -Properties ProtectedFromAccidentalDeletion, gPLink -ErrorAction SilentlyContinue
        if ($null -eq $compTarget) {
            Write-Host "VULNERABLE: The redirected Computers target container does not exist: $($currentCompContainer)" -ForegroundColor Red
            $isVulnerable = $true
        } elseif ($compTarget.ObjectClass -ne "organizationalUnit") {
            Write-Host "VULNERABLE: Computers container is redirected to object class '$($compTarget.ObjectClass)', NOT an Organizational Unit. GPOs cannot be linked directly." -ForegroundColor Red
            $isVulnerable = $true
        } else {
            Write-Host "[+] Computers container is redirected to an Organizational Unit." -ForegroundColor Green

            # Check accidental deletion protection
            if ($compTarget.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Computers OU has Accidental Deletion Protection ENABLED." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Computers OU '$($compTarget.Name)' has Accidental Deletion Protection DISABLED." -ForegroundColor Red
                $isVulnerable = $true
            }

            # Check GPO linkage
            if ([string]::IsNullOrEmpty($compTarget.gPLink)) {
                Write-Host "WARNING: Computers target OU has NO Group Policy Objects linked. Newly joined machines will not receive hardening baselines." -ForegroundColor Yellow
            } else {
                Write-Host "[+] Computers target OU has active Group Policy Object(s) linked." -ForegroundColor Green
            }
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 3. Check Users Container Redirection
    # -------------------------------------------------------------
    Write-Host "Checking Users Container Configuration..." -ForegroundColor Yellow
    $currentUserContainer = $domain.UsersContainer
    Write-Host "[i] Current Users Container: $($currentUserContainer)" -ForegroundColor Gray

    if ($currentUserContainer -eq $defaultUsersDN) {
        Write-Host "VULNERABLE: Default Users container is NOT redirected. Newly created users land in unmanaged 'CN=Users'." -ForegroundColor Red
        $isVulnerable = $true
    } else {
        # Verify the redirected container is an OU
        $userTarget = Get-ADObject -Identity $currentUserContainer -Properties ProtectedFromAccidentalDeletion, gPLink -ErrorAction SilentlyContinue
        if ($null -eq $userTarget) {
            Write-Host "VULNERABLE: The redirected Users target container does not exist: $($currentUserContainer)" -ForegroundColor Red
            $isVulnerable = $true
        } elseif ($userTarget.ObjectClass -ne "organizationalUnit") {
            Write-Host "VULNERABLE: Users container is redirected to object class '$($userTarget.ObjectClass)', NOT an Organizational Unit. GPOs cannot be linked directly." -ForegroundColor Red
            $isVulnerable = $true
        } else {
            Write-Host "[+] Users container is redirected to an Organizational Unit." -ForegroundColor Green

            # Check accidental deletion protection
            if ($userTarget.ProtectedFromAccidentalDeletion) {
                Write-Host "[+] Users OU has Accidental Deletion Protection ENABLED." -ForegroundColor Green
            } else {
                Write-Host "VULNERABLE: Users OU '$($userTarget.Name)' has Accidental Deletion Protection DISABLED." -ForegroundColor Red
                $isVulnerable = $true
            }

            # Check GPO linkage
            if ([string]::IsNullOrEmpty($userTarget.gPLink)) {
                Write-Host "WARNING: Users target OU has NO Group Policy Objects linked. Newly provisioned users will not receive hardening baselines." -ForegroundColor Yellow
            } else {
                Write-Host "[+] Users target OU has active Group Policy Object(s) linked." -ForegroundColor Green
            }
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 4. Inventory Residual Accounts in Legacy Containers
    # -------------------------------------------------------------
    Write-Host "Inventorying Residual Non-Built-in Objects in Default Containers..." -ForegroundColor Yellow

    # Residual computers in CN=Computers
    $strayComputers = Get-ADComputer -SearchBase $defaultComputersDN -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue
    if ($strayComputers) {
        $count = ($strayComputers | Measure-Object).Count
        Write-Host "WARNING: Found $($count) computer object(s) remaining in legacy default 'CN=Computers'. These should be migrated to appropriate tier OUs." -ForegroundColor Yellow
        foreach ($comp in $strayComputers | Select-Object -First 5) {
            Write-Host "  - $($comp.Name) (Enabled: $($comp.Enabled))" -ForegroundColor Gray
        }
        if ($count -gt 5) {
            Write-Host "  - ... and $($count - 5) more computer(s)." -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] Legacy default 'CN=Computers' container has no residual computer objects." -ForegroundColor Green
    }

    # Residual non-system users in CN=Users
    $builtinSids = @(
        "$($domain.DomainSID)-500", # Administrator
        "$($domain.DomainSID)-501", # Guest
        "$($domain.DomainSID)-502"  # krbtgt
    )
    $strayUsers = Get-ADUser -SearchBase $defaultUsersDN -SearchScope OneLevel -Filter * -ErrorAction SilentlyContinue | Where-Object {
        $builtinSids -notcontains $_.SID.Value -and $_.SamAccountName -ne "SUPPORT_388945a0"
    }
    if ($strayUsers) {
        $userCount = ($strayUsers | Measure-Object).Count
        Write-Host "WARNING: Found $($userCount) non-built-in user account(s) remaining in legacy default 'CN=Users'. These should be evaluated and migrated to tier OUs." -ForegroundColor Yellow
        foreach ($usr in $strayUsers | Select-Object -First 5) {
            Write-Host "  - $($usr.SamAccountName) (Enabled: $($usr.Enabled))" -ForegroundColor Gray
        }
        if ($userCount -gt 5) {
            Write-Host "  - ... and $($userCount - 5) more user(s)." -ForegroundColor Gray
        }
    } else {
        Write-Host "[+] Legacy default 'CN=Users' container contains only default built-in security principals." -ForegroundColor Green
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 5. Final Compliance Assessment
    # -------------------------------------------------------------
    if ($isVulnerable) {
        Write-Host "STATUS: NON-COMPLIANT - Default container redirection is not fully configured or protected." -ForegroundColor Red
        exit 1
    } else {
        Write-Host "STATUS: COMPLIANT - Default Users and Computers containers are properly redirected to deletion-protected Organizational Units." -ForegroundColor Green
        exit 0
    }

} catch {
    Write-Host "VULNERABLE: Failed to query Active Directory domain configuration. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
