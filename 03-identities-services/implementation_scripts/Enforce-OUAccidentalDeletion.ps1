# Enforce-OUAccidentalDeletion.ps1
# Description: Enables accidental deletion protection on all OUs in the domain.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce OU Accidental Deletion Protection..." -ForegroundColor Cyan

try {
    $UnprotectedOUs = Get-ADOrganizationalUnit -Filter "ProtectedFromAccidentalDeletion -eq '$false'" -ErrorAction Stop
    
    if ($UnprotectedOUs) {
        Write-Host "[+] Found $($UnprotectedOUs.Count) OUs requiring protection." -ForegroundColor Yellow
        foreach ($ou in $UnprotectedOUs) {
            Set-ADOrganizationalUnit -Identity $ou.DistinguishedName -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
            Write-Host "    Protected OU: $($ou.Name)" -ForegroundColor Green
        }
        Write-Host "[+] All Organizational Units are now protected." -ForegroundColor Green
    } else {
        Write-Host "[+] No unprotected OUs found." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enable protection on OUs. Error: $($_.Exception.Message)"
}
