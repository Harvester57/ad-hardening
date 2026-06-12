# Set-KerberosPreAuth.ps1
# Description: Enforces Kerberos Pre-Authentication on all active user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce Kerberos Pre-Authentication..." -ForegroundColor Cyan

try {
    $VulnerableAccounts = Get-ADUser -Filter "DoesNotRequirePreAuth -eq '$true'" -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.Enabled -eq $true }
    
    if ($VulnerableAccounts) {
        Write-Host "[+] Found $($VulnerableAccounts.Count) accounts requiring remediation." -ForegroundColor Yellow
        foreach ($acc in $VulnerableAccounts) {
            Set-ADAccountControl -Identity $acc.SamAccountName -DoesNotRequirePreAuth $false -ErrorAction Stop
            Write-Host "    Remediated: $($acc.SamAccountName)" -ForegroundColor Green
        }
        Write-Host "[+] All target accounts successfully remediated." -ForegroundColor Green
    } else {
        Write-Host "[+] No vulnerable accounts found. Pre-Authentication is already enforced." -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to enforce Kerberos Pre-Authentication. Error: $($_.Exception.Message)"
}
