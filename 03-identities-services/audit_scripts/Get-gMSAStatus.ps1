# Get-gMSAStatus.ps1
# Description: Lists all registered gMSAs and their configuration details.

Import-Module ActiveDirectory

Write-Host "--- Auditing Group Managed Service Accounts ---" -ForegroundColor Cyan

$gMSAs = Get-ADServiceAccount -Filter * -Properties Name, DNSHostName, Enabled, PrincipalsAllowedToRetrieveManagedPassword

if ($gMSAs) {
    foreach ($sa in $gMSAs) {
        Write-Host "[+] gMSA Account: $($sa.Name)" -ForegroundColor Green
        Write-Host "    - DNS Name: $($sa.DNSHostName)" -ForegroundColor White
        Write-Host "    - Enabled: $($sa.Enabled)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No Group Managed Service Accounts found in the Active Directory domain." -ForegroundColor Yellow
}
