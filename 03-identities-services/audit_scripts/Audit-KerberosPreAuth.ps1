# Audit-KerberosPreAuth.ps1
# Description: Audits active user accounts to find any with pre-authentication disabled.

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberos Pre-Authentication Status ---" -ForegroundColor Cyan

try {
    # Search for enabled accounts with DONOTREQ_PREAUTH (0x400000) active
    $VulnerableAccounts = Get-ADUser -Filter "DoesNotRequirePreAuth -eq '$true'" -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.Enabled -eq $true }
    
    if ($VulnerableAccounts) {
        Write-Host "`nVULNERABLE: Found $($VulnerableAccounts.Count) enabled user account(s) with Kerberos Pre-Authentication disabled:" -ForegroundColor Red
        foreach ($acc in $VulnerableAccounts) {
            Write-Host "    - User: $($acc.SamAccountName) | DN: $($acc.DistinguishedName)" -ForegroundColor White
        }
    } else {
        Write-Host "`nStatus: Compliant. All enabled user accounts require Kerberos Pre-Authentication." -ForegroundColor Green
    }
} catch {
    Write-Host "VULNERABLE: Could not audit accounts. Error: $($_.Exception.Message)" -ForegroundColor Red
}
