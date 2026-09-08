# Set-DefaultContainersRedirection.ps1
# Description: Creates staging OUs, configures accidental deletion protection,
#              and redirects default user and computer containers using redircmp and redirusr.
# Target Engine: Windows PowerShell 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [string]$TargetComputersOUName = "Staging-Computers",

    [Parameter(Mandatory = $false)]
    [string]$TargetUsersOUName = "Staging-Users",

    [Parameter(Mandatory = $false)]
    [string]$ParentOUPath
)

Write-Host "--- Applying Hardening: Redirect Default Users and Computers Containers ---" -ForegroundColor Cyan

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    exit 1
}

Import-Module ActiveDirectory

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainDN = $domain.DistinguishedName

    # Determine base path
    if ([string]::IsNullOrEmpty($ParentOUPath)) {
        $basePath = $domainDN
    } else {
        $basePath = $ParentOUPath
    }

    $targetComputersDN = "OU=$($TargetComputersOUName),$($basePath)"
    $targetUsersDN = "OU=$($TargetUsersOUName),$($basePath)"

    Write-Host "[i] Target Computers OU DN: $($targetComputersDN)" -ForegroundColor Gray
    Write-Host "[i] Target Users OU DN    : $($targetUsersDN)" -ForegroundColor Gray
    Write-Host ""

    # -------------------------------------------------------------
    # 2. Provision and Protect Computers Staging OU
    # -------------------------------------------------------------
    $existingCompOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($targetComputersDN)'" -ErrorAction SilentlyContinue
    if ($null -eq $existingCompOU) {
        if ($PSCmdlet.ShouldProcess($targetComputersDN, "Create Organizational Unit and enable Accidental Deletion Protection")) {
            Write-Host "[+] Creating target Computers OU: $($targetComputersDN)" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $TargetComputersOUName -Path $basePath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Target Computers OU created and protected successfully." -ForegroundColor Green
        }
    } else {
        Write-Host "[+] Target Computers OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($targetComputersDN, "Set ProtectedFromAccidentalDeletion = $true")) {
            Set-ADOrganizationalUnit -Identity $targetComputersDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Accidental deletion protection verified on Computers OU." -ForegroundColor Green
        }
    }

    # -------------------------------------------------------------
    # 3. Provision and Protect Users Staging OU
    # -------------------------------------------------------------
    $existingUserOU = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$($targetUsersDN)'" -ErrorAction SilentlyContinue
    if ($null -eq $existingUserOU) {
        if ($PSCmdlet.ShouldProcess($targetUsersDN, "Create Organizational Unit and enable Accidental Deletion Protection")) {
            Write-Host "[+] Creating target Users OU: $($targetUsersDN)" -ForegroundColor Yellow
            New-ADOrganizationalUnit -Name $TargetUsersOUName -Path $basePath -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Target Users OU created and protected successfully." -ForegroundColor Green
        }
    } else {
        Write-Host "[+] Target Users OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        if ($PSCmdlet.ShouldProcess($targetUsersDN, "Set ProtectedFromAccidentalDeletion = $true")) {
            Set-ADOrganizationalUnit -Identity $targetUsersDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "[+] Accidental deletion protection verified on Users OU." -ForegroundColor Green
        }
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 4. Redirect Computers Container via redircmp.exe
    # -------------------------------------------------------------
    if ($domain.ComputersContainer -ne $targetComputersDN) {
        if ($PSCmdlet.ShouldProcess($domainDN, "Redirect Computers Container to $($targetComputersDN)")) {
            Write-Host "[+] Redirecting default Computers container to: $($targetComputersDN)..." -ForegroundColor Yellow
            $outputComp = & redircmp.exe $targetComputersDN 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] redircmp output: $($outputComp)" -ForegroundColor Green
            } else {
                throw "redircmp.exe failed with exit code $($LASTEXITCODE). Output: $($outputComp)"
            }
        }
    } else {
        Write-Host "[+] Computers container is already redirected to target OU: $($targetComputersDN)" -ForegroundColor Green
    }

    # -------------------------------------------------------------
    # 5. Redirect Users Container via redirusr.exe
    # -------------------------------------------------------------
    if ($domain.UsersContainer -ne $targetUsersDN) {
        if ($PSCmdlet.ShouldProcess($domainDN, "Redirect Users Container to $($targetUsersDN)")) {
            Write-Host "[+] Redirecting default Users container to: $($targetUsersDN)..." -ForegroundColor Yellow
            $outputUser = & redirusr.exe $targetUsersDN 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[+] redirusr output: $($outputUser)" -ForegroundColor Green
            } else {
                throw "redirusr.exe failed with exit code $($LASTEXITCODE). Output: $($outputUser)"
            }
        }
    } else {
        Write-Host "[+] Users container is already redirected to target OU: $($targetUsersDN)" -ForegroundColor Green
    }

    Write-Host ""

    # -------------------------------------------------------------
    # 6. Post-Remediation Verification
    # -------------------------------------------------------------
    $refreshedDomain = Get-ADDomain -ErrorAction Stop
    Write-Host "Post-Remediation Verification:" -ForegroundColor Cyan
    Write-Host "  - Domain ComputersContainer: $($refreshedDomain.ComputersContainer)" -ForegroundColor Gray
    Write-Host "  - Domain UsersContainer    : $($refreshedDomain.UsersContainer)" -ForegroundColor Gray

    if ($refreshedDomain.ComputersContainer -eq $targetComputersDN -and $refreshedDomain.UsersContainer -eq $targetUsersDN) {
        Write-Host "`n[+] Default containers redirection completed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Directory attributes have not yet reflected the redirection. Allow time for domain-wide replication."
    }

    Write-Host ""
    Write-Host "[IMPORTANT NEXT STEPS]:" -ForegroundColor Yellow
    Write-Host "1. Link a quarantine/staging Group Policy Object (GPO) to '$($targetComputersDN)' (enforcing LAPS, Firewall, Credential Guard)." -ForegroundColor Gray
    Write-Host "2. Delegate 'Create Computer Objects' on '$($targetComputersDN)' to authorized provisioning service accounts." -ForegroundColor Gray
    Write-Host "3. Inventory and migrate any non-built-in residual accounts from 'CN=Computers' and 'CN=Users' to appropriate production OUs." -ForegroundColor Gray

} catch {
    Write-Error "Remediation failed. Error: $($_.Exception.Message)"
    exit 1
}
