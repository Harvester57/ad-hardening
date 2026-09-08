# Enable-ADRecycleBin.ps1
# Description: Validates forest prerequisites, enables Active Directory Recycle Bin forest-wide, and configures lifetimes.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Applying Hardening Requirement: Enable Active Directory Recycle Bin ---" -ForegroundColor Cyan

# 1. Verify Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required to execute this script."
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # 2. Forest and FFL Validation
    $forest = Get-ADForest -ErrorAction Stop
    $forestMode = $forest.ForestMode

    Write-Host "[*] Target Forest: $($forest.Name)" -ForegroundColor Gray
    Write-Host "[*] Current Forest Functional Level: $($forestMode)" -ForegroundColor Gray

    $validModes = @("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest", "Windows2025Forest")
    if ($validModes -notcontains $forestMode) {
        Write-Error "Cannot enable Recycle Bin. Forest functional level must be Windows Server 2008 R2 or higher (Current: $($forestMode)). Raise forest functional level first."
        return
    }

    # 3. Check and Enable Recycle Bin Feature
    $recycleBinFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -ErrorAction Stop
    $enabledScopes = $recycleBinFeature.EnabledScopes

    if (-not $enabledScopes -or $enabledScopes.Count -eq 0) {
        Write-Host "[+] Enabling Active Directory Recycle Bin optional feature in forest '$($forest.Name)'..." -ForegroundColor Yellow
        Enable-ADOptionalFeature -Identity $recycleBinFeature -Scope ForestOrConfigurationSet -Target $forest.Name -Confirm:$false -ErrorAction Stop
        Write-Host "[+] Active Directory Recycle Bin enabled successfully." -ForegroundColor Green
    } else {
        Write-Host "[+] Active Directory Recycle Bin is already enabled in forest '$($forest.Name)'." -ForegroundColor Green
    }

    # 4. Configure / Verify msDS-deletedObjectLifetime
    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $configNC = $rootDse.configurationNamingContext
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNC"

    $dsConfig = Get-ADObject -Identity $dsPath -Properties msDS-deletedObjectLifetime, tombstoneLifetime -ErrorAction Stop
    $tombstone = $dsConfig.tombstoneLifetime
    $currentDol = $dsConfig."msDS-deletedObjectLifetime"

    # Ensure tombstoneLifetime is at least 180 days
    if ($null -eq $tombstone -or $tombstone -lt 180) {
        Write-Host "[+] Setting tombstoneLifetime to 180 days on Directory Service configuration..." -ForegroundColor Yellow
        Set-ADObject -Identity $dsPath -Replace @{ tombstoneLifetime = 180 } -ErrorAction Stop
        Write-Host "[+] tombstoneLifetime updated to 180 days." -ForegroundColor Green
    } else {
        Write-Host "[+] tombstoneLifetime is currently configured to $($tombstone) days." -ForegroundColor Green
    }

    # Set explicit msDS-deletedObjectLifetime if missing or excessively low
    if ($null -eq $currentDol -or $currentDol -lt 180) {
        Write-Host "[+] Explicitly configuring msDS-deletedObjectLifetime to 180 days..." -ForegroundColor Yellow
        Set-ADObject -Identity $dsPath -Replace @{ "msDS-deletedObjectLifetime" = 180 } -ErrorAction Stop
        Write-Host "[+] msDS-deletedObjectLifetime configured to 180 days." -ForegroundColor Green
    } else {
        Write-Host "[+] msDS-deletedObjectLifetime is currently set to $($currentDol) days." -ForegroundColor Green
    }

    Write-Host "[+] Remediation completed successfully. Allow directory replication to synchronize across all Domain Controllers." -ForegroundColor Green

} catch {
    Write-Error "Failed to configure Active Directory Recycle Bin. Error: $($_.Exception.Message)"
}
