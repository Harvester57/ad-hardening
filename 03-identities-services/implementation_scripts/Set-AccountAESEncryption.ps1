# Set-AccountAESEncryption.ps1
# Description: Configures the msDS-SupportedEncryptionTypes attribute to AES-only (24) on active user accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce AES-Only Kerberos Encryption on Accounts..." -ForegroundColor Cyan

# 24 represents AES128 (8) + AES256 (16)
$AESValue = 24
$TargetUsers = Get-ADUser -Filter {Enabled -eq $true}

foreach ($User in $TargetUsers) {
    # Retrieve current attribute value
    $currUser = Get-ADUser -Identity $User -Properties msDS-SupportedEncryptionTypes
    $currVal = $currUser."msDS-SupportedEncryptionTypes"
    
    if ($currVal -ne $AESValue) {
        Write-Host "[*] Enforcing AES encryption on account: $($User.SamAccountName)" -ForegroundColor Gray
        Set-ADUser -Identity $User -Replace @{"msDS-SupportedEncryptionTypes" = $AESValue}
    }
}

Write-Host "AES encryption has been successfully enforced on active accounts." -ForegroundColor Green
