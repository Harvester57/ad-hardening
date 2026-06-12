# Audit-OUAccidentalDeletion.ps1
# Description: Audits all OUs to find any without accidental deletion protection.

Import-Module ActiveDirectory

Write-Host "--- Auditing OU Accidental Deletion Protection ---" -ForegroundColor Cyan

try {
    $UnprotectedOUs = Get-ADOrganizationalUnit -Filter "ProtectedFromAccidentalDeletion -eq '$false'" -ErrorAction Stop
    
    if ($UnprotectedOUs) {
        Write-Host "`nVULNERABLE: Found $($UnprotectedOUs.Count) Organizational Unit(s) without accidental deletion protection:" -ForegroundColor Red
        foreach ($ou in $UnprotectedOUs) {
            Write-Host "    - OU: $($ou.Name) | DN: $($ou.DistinguishedName)" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. All Organizational Units are protected from accidental deletion." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit OUs. Error: $($_.Exception.Message)" -ForegroundColor Red
}
