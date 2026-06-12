# Reset-KrbtgtPassword.ps1
# Description: Resets the password of the krbtgt account with a strong, random password.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: KRBTGT Password Rotation..." -ForegroundColor Cyan

# 1. Retrieve the krbtgt account
$Krbtgt = Get-ADUser -Filter "Name -eq 'krbtgt'" -Properties PasswordLastSet, Enabled
if (-not $Krbtgt) {
    Write-Error "KRBTGT account not found in the Active Directory domain."
    return
}

Write-Host "Current KRBTGT Password Last Set: $($Krbtgt.PasswordLastSet)" -ForegroundColor White

# 2. Generate a strong random password (128 characters)
$Length = 128
$Chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-="
$RandomPassword = -join (1..$Length | ForEach-Object { $Chars[(Get-Random -Maximum $Chars.Length)] })

$SecurePassword = New-Object System.Security.SecureString
foreach ($Char in $RandomPassword.ToCharArray()) {
    $SecurePassword.AppendChar($Char)
}

# 3. Apply the password change
try {
    Set-ADAccountPassword -Identity $Krbtgt -NewPassword $SecurePassword -Reset -ErrorAction Stop
    Write-Host "[OK] KRBTGT password has been successfully reset." -ForegroundColor Green
    Write-Host "[IMPORTANT] This is a single password reset." -ForegroundColor Yellow
    Write-Host "[IMPORTANT] To fully invalidate old Kerberos tickets (e.g., to recover from Golden Ticket compromise)," -ForegroundColor Yellow
    Write-Host "            you MUST perform a second reset AFTER all domain controllers have replicated the first reset" -ForegroundColor Yellow
    Write-Host "            and the maximum Kerberos ticket lifetime (default 10 hours) has elapsed." -ForegroundColor Yellow
} catch {
    Write-Error "Failed to reset KRBTGT password: $($_.Exception.Message)"
}
