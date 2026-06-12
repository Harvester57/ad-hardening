# Configure-LAPS.ps1
# Description: Configures Windows LAPS parameters in the registry.

Write-Host "Applying hardening requirement: Enable Local Administrator Password Solution..." -ForegroundColor Cyan

$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\LAPS"

if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# 1 = Backup to Active Directory
Set-ItemProperty -Path $RegPath -Name "BackupDirectory" -Value 1 -Type DWord
# 4 = Letters + numbers + special characters
Set-ItemProperty -Path $RegPath -Name "PasswordComplexity" -Value 4 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordLength" -Value 20 -Type DWord
Set-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -Value 30 -Type DWord

Write-Host "Windows LAPS configuration registry settings applied successfully." -ForegroundColor Green
