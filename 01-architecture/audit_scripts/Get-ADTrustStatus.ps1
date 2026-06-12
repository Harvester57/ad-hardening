# Get-ADTrustStatus.ps1
# Description: Audits trust attributes and configuration settings.

Import-Module ActiveDirectory

Write-Host "--- Auditing Trust Relationships ---" -ForegroundColor Cyan

$Trusts = Get-ADTrust -Filter * -Properties *

if ($Trusts) {
    foreach ($Trust in $Trusts) {
        Write-Host "[+] Trust Name: $($Trust.Name)" -ForegroundColor Green
        Write-Host "    - Trust Type: $($Trust.TrustType)" -ForegroundColor White
        Write-Host "    - Direction: $($Trust.TrustDirection)" -ForegroundColor White
        Write-Host "    - Selective Authentication: $($Trust.SelectiveAuthentication)" -ForegroundColor White
        Write-Host "    - Disallow Transitivity: $($Trust.DisallowTransitivity)" -ForegroundColor White
        
        # Verify specific settings using netdom query
        Write-Host "    - netdom Configuration Details:" -ForegroundColor White
        netdom trust $Trust.Source /domain:$Trust.Target /Query
    }
} else {
    Write-Host "[-] No trust relationships found in the domain." -ForegroundColor Yellow
}
