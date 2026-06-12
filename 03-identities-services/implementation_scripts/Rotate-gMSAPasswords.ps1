# Rotate-gMSAPasswords.ps1
# Description: Forces password rotation for all gMSAs.

Import-Module ActiveDirectory

Write-Host "Locating all gMSAs in the domain..." -ForegroundColor Cyan

$gMSAs = Get-ADServiceAccount -Filter "ObjectClass -eq 'msDS-GroupManagedServiceAccount'"

if ($gMSAs) {
    foreach ($Acct in $gMSAs) {
        Write-Host "[*] Rotating password for gMSA: $($Acct.Name)..." -ForegroundColor White
        
        # Reset password (forces rotation on the next request by the host computer)
        Reset-ADServiceAccountPassword -Identity $Acct.DistinguishedName -ErrorAction Stop
        
        Write-Host "[+] Password rotated successfully for $($Acct.Name)." -ForegroundColor Green
    }
} else {
    Write-Host "[-] No Group Managed Service Accounts found." -ForegroundColor Yellow
}
