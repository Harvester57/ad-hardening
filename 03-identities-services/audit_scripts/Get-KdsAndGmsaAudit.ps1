# Get-KdsAndGmsaAudit.ps1
# Description: Audits active KDS root keys and checks gMSA accounts.

Import-Module ActiveDirectory
Import-Module Kds

Write-Host "--- Auditing KDS Root Keys ---" -ForegroundColor Cyan

$KdsKeys = Get-KdsRootKey -ErrorAction SilentlyContinue

if ($KdsKeys) {
    foreach ($Key in $KdsKeys) {
        Write-Host "[+] KDS Key ID:     $($Key.KeyId)" -ForegroundColor Green
        Write-Host "    - Created:       $($Key.CreateTime)" -ForegroundColor White
        Write-Host "    - Effective:     $($Key.EffectiveTime)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No KDS Root Keys found in the forest." -ForegroundColor Red
}

Write-Host "--- Auditing gMSA Accounts ---" -ForegroundColor Cyan

$Accounts = Get-ADServiceAccount -Filter * -Properties msDS-ManagedPasswordInterval, msDS-HostSecurityGroupsScope

if ($Accounts) {
    foreach ($Acct in $Accounts) {
        Write-Host "[*] gMSA: $($Acct.Name)" -ForegroundColor White
        Write-Host "    - Rotation Interval: $($Acct.'msDS-ManagedPasswordInterval') days" -ForegroundColor Gray
    }
} else {
    Write-Host "[-] No service accounts found." -ForegroundColor Yellow
}
