# Audit-ADRecycleBin.ps1
# Description: Audits Active Directory Recycle Bin status, lifetime configurations, and container ACL permissions.
# Target Engine: Windows PowerShell 5.1

Write-Host "--- Auditing Active Directory Recycle Bin Configuration ---" -ForegroundColor Cyan

$isVulnerable = $false

# 1. Verify Active Directory module availability
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "VULNERABLE: The ActiveDirectory PowerShell module is not available on this system." -ForegroundColor Red
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    return
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

try {
    # 2. Check Forest and Forest Functional Level
    $forest = Get-ADForest -ErrorAction Stop
    $forestMode = $forest.ForestMode

    Write-Host "[*] Active Directory Forest: $($forest.Name)" -ForegroundColor Gray
    Write-Host "[*] Forest Functional Level: $($forestMode)" -ForegroundColor Gray

    $validModes = @("Windows2008R2Forest", "Windows2012Forest", "Windows2012R2Forest", "Windows2016Forest", "Windows2025Forest")
    if ($validModes -notcontains $forestMode) {
        Write-Host "VULNERABLE: Forest Functional Level '$($forestMode)' does not support Active Directory Recycle Bin (requires Windows Server 2008 R2 or higher)." -ForegroundColor Red
        $isVulnerable = $true
    }

    # 3. Check Optional Feature Enablement
    $recycleFeature = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'" -Properties EnabledScopes -ErrorAction Stop
    $enabledScopes = $recycleFeature.EnabledScopes

    if ($enabledScopes -and ($enabledScopes -contains $forest.PartitionsContainer -or $enabledScopes.Count -gt 0)) {
        Write-Host "[+] Recycle Bin Feature is ENABLED forest-wide." -ForegroundColor Green
    } else {
        Write-Host "VULNERABLE: Active Directory Recycle Bin Feature is NOT enabled in forest '$($forest.Name)'." -ForegroundColor Red
        $isVulnerable = $true
    }

    # 4. Check Deleted Object Lifetime and Tombstone Lifetime
    $rootDse = Get-ADRootDSE -ErrorAction Stop
    $configNC = $rootDse.configurationNamingContext
    $dsPath = "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$configNC"

    $dsConfig = Get-ADObject -Identity $dsPath -Properties msDS-deletedObjectLifetime, tombstoneLifetime -ErrorAction Stop
    $dol = $dsConfig."msDS-deletedObjectLifetime"
    $tombstone = $dsConfig.tombstoneLifetime

    if ($null -eq $tombstone -or $tombstone -eq 0) {
        $effectiveTombstone = 60 # Legacy Windows 2000/2003 default
        Write-Host "[!] tombstoneLifetime attribute is not explicitly set (defaults to 60 days in legacy forests, or 180 days in modern forests)." -ForegroundColor Yellow
    } else {
        $effectiveTombstone = $tombstone
        Write-Host "[*] tombstoneLifetime: $($effectiveTombstone) days" -ForegroundColor Gray
    }

    if ($null -eq $dol) {
        Write-Host "[*] msDS-deletedObjectLifetime: (Not Set - defaults to tombstoneLifetime of $($effectiveTombstone) days)" -ForegroundColor Gray
    } else {
        Write-Host "[*] msDS-deletedObjectLifetime: $($dol) days" -ForegroundColor Gray
        if ($dol -lt 60) {
            Write-Host "VULNERABLE: msDS-deletedObjectLifetime is configured to less than 60 days ($($dol) days). Recovery window is excessively short." -ForegroundColor Red
            $isVulnerable = $true
        }
    }

    # 5. Audit Access Permissions on CN=Deleted Objects Container
    $domainDN = $rootDse.defaultNamingContext
    $deletedObjectsDN = "CN=Deleted Objects,$domainDN"

    Write-Host "[*] Auditing security permissions on: $($deletedObjectsDN)" -ForegroundColor Gray

    try {
        $deletedObjACL = Get-Acl -Path "AD:\$deletedObjectsDN" -ErrorAction Stop
        $suspiciousIdentities = @(
            "NT AUTHORITY\Authenticated Users",
            "Everyone",
            "BUILTIN\Users",
            "ANONYMOUS LOGON"
        )

        $flaggedAccess = $false
        foreach ($accessRule in $deletedObjACL.Access) {
            $identity = $accessRule.IdentityReference.Value
            foreach ($suspicious in $suspiciousIdentities) {
                if ($identity -like "*$suspicious*" -and $accessRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                    Write-Host "VULNERABLE: Non-default permissive access granted to '$($identity)' on Deleted Objects container ($($accessRule.ActiveDirectoryRights))." -ForegroundColor Red
                    $flaggedAccess = $true
                    $isVulnerable = $true
                }
            }
        }

        if (-not $flaggedAccess) {
            Write-Host "[+] Permissions on Deleted Objects container are restricted to privileged administrators." -ForegroundColor Green
        }
    } catch {
        Write-Host "[*] Note: Unable to query Deleted Objects container ACL directly ($($_.Exception.Message))." -ForegroundColor Yellow
    }

} catch {
    Write-Host "VULNERABLE: Failed to complete Active Directory Recycle Bin audit. Error: $($_.Exception.Message)" -ForegroundColor Red
    $isVulnerable = $true
}

Write-Host "--------------------------------------------------------" -ForegroundColor Cyan
if ($isVulnerable) {
    Write-Host "Audit Result: VULNERABLE - Active Directory Recycle Bin configuration requires remediation." -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE - Active Directory Recycle Bin is enabled and correctly configured." -ForegroundColor Green
}
