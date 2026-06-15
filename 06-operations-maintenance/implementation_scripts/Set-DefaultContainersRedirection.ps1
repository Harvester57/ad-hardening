# Set-DefaultContainersRedirection.ps1
# Description: Creates new OUs, protects them from accidental deletion, and redirects default users/computers containers.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Redirect Default Containers to Protected OUs..." -ForegroundColor Cyan

try {
    $Domain = Get-ADDomain -ErrorAction Stop
    $DomainDN = $Domain.DistinguishedName
    $TargetComputersOU = "OU=New-Computers,$($DomainDN)"
    $TargetUsersOU = "OU=New-Users,$($DomainDN)"
    
    # 1. Create and protect target Computers OU
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetComputersOU'")) {
        Write-Host "[+] Creating target Computers OU: New-Computers" -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "New-Computers" -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Computers OU created and protected successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Target Computers OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        Set-ADOrganizationalUnit -Identity $TargetComputersOU -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Accidental deletion protection verified on target Computers OU." -ForegroundColor Green
    }
    
    # 2. Create and protect target Users OU
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$TargetUsersOU'")) {
        Write-Host "[+] Creating target Users OU: New-Users" -ForegroundColor Yellow
        New-ADOrganizationalUnit -Name "New-Users" -Path $DomainDN -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Users OU created and protected successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Target Users OU already exists. Ensuring accidental deletion protection is enabled..." -ForegroundColor Yellow
        Set-ADOrganizationalUnit -Identity $TargetUsersOU -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
        Write-Host "[+] Accidental deletion protection verified on target Users OU." -ForegroundColor Green
    }
    
    # 3. Perform Computers Redirection
    if ($Domain.ComputersContainer -ne $TargetComputersOU) {
        Write-Host "[+] Redirecting default Computers container to $TargetComputersOU..." -ForegroundColor Yellow
        $Output = & redircmp.exe $TargetComputersOU 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Computers container redirected successfully." -ForegroundColor Green
        } else {
            throw "Failed to redirect Computers container: $($Output)"
        }
    } else {
        Write-Host "[+] Computers container is already redirected to target OU." -ForegroundColor Green
    }
    
    # 4. Perform Users Redirection
    if ($Domain.UsersContainer -ne $TargetUsersOU) {
        Write-Host "[+] Redirecting default Users container to $TargetUsersOU..." -ForegroundColor Yellow
        $Output = & redirusr.exe $TargetUsersOU 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Users container redirected successfully." -ForegroundColor Green
        } else {
            throw "Failed to redirect Users container: $($Output)"
        }
    } else {
        Write-Host "[+] Users container is already redirected to target OU." -ForegroundColor Green
    }
    
    Write-Host "`n[+] Redirection operations completed successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply redirection. Error: $($_.Exception.Message)"
    exit 1
}
