# Get-AccountEncryptionStatus.ps1
# Description: Identifies accounts that do not have msDS-SupportedEncryptionTypes set to 24 (AES-only).

Import-Module ActiveDirectory

Write-Host "--- Auditing Account Kerberos Encryption Configuration ---" -ForegroundColor Cyan

$VulnerableAccounts = Get-ADUser -Filter {Enabled -eq $true} -Properties msDS-SupportedEncryptionTypes | Where-Object { $_."msDS-SupportedEncryptionTypes" -ne 24 }

if ($VulnerableAccounts) {
    Write-Host "[!] Accounts not configured for AES-only (msDS-SupportedEncryptionTypes != 24):" -ForegroundColor Red
    foreach ($Acct in $VulnerableAccounts) {
        $Val = $Acct."msDS-SupportedEncryptionTypes"
        if ($null -eq $Val) { $Val = "Not Set (0)" }
        Write-Host "    - $($Acct.SamAccountName) | Value: $Val" -ForegroundColor White
    }
} else {
    Write-Host "[+] Secure: All active accounts are configured for AES-only Kerberos encryption." -ForegroundColor Green
}
