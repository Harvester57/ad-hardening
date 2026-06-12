# Get-AuthSiloAuditStatus.ps1
# Description: Queries the active Authentication Silos and lists their configuration settings.

Import-Module ActiveDirectory

Write-Host "--- Auditing Authentication Silos ---" -ForegroundColor Cyan

$Silos = Get-ADAuthenticationPolicySilo -Filter * -Properties *

if ($Silos) {
    foreach ($Silo in $Silos) {
        Write-Host "[+] Silo Name: $($Silo.Name)" -ForegroundColor Green
        Write-Host "    - Enforced: $($Silo.Enforce)" -ForegroundColor White
        Write-Host "    - User Policy: $($Silo.UserAuthenticationPolicy)" -ForegroundColor White
        Write-Host "    - Computer Policy: $($Silo.ComputerAuthenticationPolicy)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No Authentication Policy Silos configured in this domain." -ForegroundColor Yellow
}
