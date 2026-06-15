# Configure-LAPS.ps1
# Description: Configures Windows LAPS parameters in the registry.

Write-Host "Applying hardening requirement: Enable Local Administrator Password Solution..." -ForegroundColor Cyan

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Enable LAPS management
Set-ItemProperty -Path $RegPath -Name "EnableLAPS" -Value 1 -Type DWord
# 2 = Backup to Active Directory
Set-ItemProperty -Path $RegPath -Name "BackupDirectory" -Value 2 -Type DWord
# 1 = Do not allow password expiration time longer than required by policy
Set-ItemProperty -Path $RegPath -Name "PasswordExpirationProtectionEnabled" -Value 1 -Type DWord
# 1 = Enable password encryption
Set-ItemProperty -Path $RegPath -Name "ADPasswordEncryptionEnabled" -Value 1 -Type DWord
# 4 = Letters + numbers + special characters
Set-ItemProperty -Path $RegPath -Name "PasswordComplexity" -Value 4 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordLength" -Value 20 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -Value 30 -Type DWord
# 8 = Grace period of 8 hours
Set-ItemProperty -Path $RegPath -Name "PostAuthenticationResetDelay" -Value 8 -Type DWord
# 3 = Reset the password and logoff the managed account
Set-ItemProperty -Path $RegPath -Name "PostAuthenticationActions" -Value 3 -Type DWord

Write-Host "Windows LAPS configuration registry settings applied successfully." -ForegroundColor Green
