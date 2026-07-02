# Get-KerberoastHoneypotStatus.ps1
# Description: Audits the existence, SPN, AdminCount, and logon restrictions of the Kerberoasting honeypot account.
# Target Engine: Windows PowerShell 5.1

Import-Module ActiveDirectory

Write-Host "--- Auditing Kerberoasting Honeypot Configuration ---" -ForegroundColor Cyan

$HoneypotName = "krbtgt_honey"
$HoneypotSPN = "MSSQLSvc/sql-backup-prod.domain.local:1433"

# 1. Retrieve the honeypot account
$User = Get-ADUser -Filter "SamAccountName -eq '$HoneypotName'" -Properties servicePrincipalName, adminCount, LogonWorkstations

if (-not $User) {
    Write-Host "[-] Decoy user account '$HoneypotName' does not exist." -ForegroundColor Red
    exit 1
}

$IsCompliant = $true

# 2. Verify SPN is registered
$SPNExists = $User.servicePrincipalName | Where-Object { $_ -eq $HoneypotSPN }
if ($SPNExists) {
    Write-Host "[+] Decoy SPN '$HoneypotSPN' is registered on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[!] Decoy SPN '$HoneypotSPN' is NOT registered on '$HoneypotName'." -ForegroundColor Red
    $IsCompliant = $false
}

# 3. Verify AdminCount is set to 1
if ($User.adminCount -eq 1) {
    Write-Host "[+] AdminCount is set to 1 (deceptive marker active)." -ForegroundColor Green
} else {
    Write-Host "[!] AdminCount is NOT set to 1 on '$HoneypotName'." -ForegroundColor Red
    $IsCompliant = $false
}

# 4. Verify LogonWorkstations restriction
if ($User.LogonWorkstations -like "*HONEYPOT-VOID-HOST*") {
    Write-Host "[+] Logon restrictions enforced (LogonWorkstations contains 'HONEYPOT-VOID-HOST')." -ForegroundColor Green
} else {
    Write-Host "[!] Logon restrictions NOT enforced on '$HoneypotName' (LogonWorkstations: '$($User.LogonWorkstations)')." -ForegroundColor Red
    $IsCompliant = $false
}

if ($IsCompliant) {
    Write-Host "[+] Secure: Kerberoasting Honeypot is fully configured and active." -ForegroundColor Green
    exit 0
} else {
    Write-Host "[-] Non-Compliant: Kerberoasting Honeypot configurations are incomplete." -ForegroundColor Red
    exit 1
}
