# Set-ADFunctionalLevels.ps1
# Description: Raises Domain and Forest Functional Levels to Windows Server 2016.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Raise Functional Levels to Windows Server 2016..." -ForegroundColor Cyan

$Domain = Get-ADDomain -ErrorAction SilentlyContinue
$Forest = Get-ADForest -ErrorAction SilentlyContinue

if (-not $Domain -or -not $Forest) {
    Write-Error "Could not retrieve Active Directory settings. Run on a Domain Controller with administrative privileges."
    exit 1
}

# Raise Domain Functional Level
if ($Domain.DomainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2016Domain) {
    try {
        Set-ADDomainMode -Identity $Domain.DNSRoot -DomainMode Windows2016Domain -Confirm:$false -ErrorAction Stop
        Write-Host "Domain Functional Level successfully raised to Windows Server 2016." -ForegroundColor Green
    } catch {
        Write-Error "Failed to raise Domain Functional Level. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Domain Functional Level is already Windows Server 2016 or higher." -ForegroundColor Green
}

# Raise Forest Functional Level
if ($Forest.ForestMode -lt [Microsoft.ActiveDirectory.Management.ADForestMode]::Windows2016Forest) {
    try {
        Set-ADForestMode -Identity $Forest.Name -ForestMode Windows2016Forest -Confirm:$false -ErrorAction Stop
        Write-Host "Forest Functional Level successfully raised to Windows Server 2016." -ForegroundColor Green
    } catch {
        Write-Error "Failed to raise Forest Functional Level. Error: $($_.Exception.Message)"
    }
} else {
    Write-Host "Forest Functional Level is already Windows Server 2016 or higher." -ForegroundColor Green
}
