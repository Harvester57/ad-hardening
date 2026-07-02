# New-KerberoastHoneypot.ps1
# Description: Configures a decoy Kerberoasting Honeypot account with a fake SPN, AdminCount=1, and restricted logon capabilities.
# Target Engine: Windows PowerShell 5.1

[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
param()

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Configure Kerberoasting Honeypot..." -ForegroundColor Cyan

$HoneypotName = "krbtgt_honey"
$HoneypotSPN = "MSSQLSvc/sql-backup-prod.domain.local:1433"
$HoneypotDescription = "Decoy service account for backup database monitoring."

# 1. Check if the honeypot user account already exists
$ExistingUser = Get-ADUser -Filter "SamAccountName -eq '$HoneypotName'"

if (-not $ExistingUser) {
    # Generate a complex 120-character password to prevent cracking
    $Characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    $RandomPassword = ""
    for ($i = 0; $i -lt 120; $i++) {
        $Index = Get-Random -Minimum 0 -Maximum $Characters.Length
        $RandomPassword += $Characters[$Index]
    }
    
    $SecurePassword = ConvertTo-SecureString $RandomPassword -AsPlainText -Force

    # Create the AD User.
    # Set LogonWorkstations to a non-existent host to prevent logon attempts.
    # UPN domain suffix should match the root domain.
    $Domain = Get-ADDomain
    New-ADUser -Name $HoneypotName `
               -SamAccountName $HoneypotName `
               -UserPrincipalName "$HoneypotName@$($Domain.DNSRoot)" `
               -AccountPassword $SecurePassword `
               -Enabled $true `
               -Description $HoneypotDescription `
               -LogonWorkstations "HONEYPOT-VOID-HOST" `
               -PasswordNeverExpires $true

    Write-Host "[+] Decoy user account '$HoneypotName' created with logon restrictions." -ForegroundColor Green
} else {
    Write-Host "[*] Decoy user account '$HoneypotName' already exists." -ForegroundColor Yellow
}

# 2. Configure target attributes: AdminCount, ServicePrincipalName
$UserObj = Get-ADUser -Identity $HoneypotName -Properties servicePrincipalName, adminCount

# Set AdminCount to 1 (highly attractive to scanners)
if ($UserObj.adminCount -ne 1) {
    Set-ADUser -Identity $HoneypotName -Replace @{adminCount = 1}
    Write-Host "[+] Set AdminCount to 1 on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[*] AdminCount is already set to 1." -ForegroundColor Yellow
}

# Set Service Principal Name
$SPNExists = $UserObj.servicePrincipalName | Where-Object { $_ -eq $HoneypotSPN }
if (-not $SPNExists) {
    Set-ADUser -Identity $HoneypotName -Add @{servicePrincipalName = $HoneypotSPN}
    Write-Host "[+] Service Principal Name '$HoneypotSPN' registered on '$HoneypotName'." -ForegroundColor Green
} else {
    Write-Host "[*] Service Principal Name '$HoneypotSPN' already registered." -ForegroundColor Yellow
}

Write-Host "Honeypot configuration applied successfully." -ForegroundColor Green
