# Get-LAPSStatus.ps1
# Description: Checks the Windows LAPS registry parameters.

Write-Host "--- Auditing LAPS Registry Configuration ---" -ForegroundColor Cyan

$RegPath = "HKLM:\Software\Policies\Microsoft\Windows\LAPS"

if (Test-Path $RegPath) {
    $backupDir = Get-ItemProperty -Path $RegPath -Name "BackupDirectory" -ErrorAction SilentlyContinue
    $complexity = Get-ItemProperty -Path $RegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
    $length = Get-ItemProperty -Path $RegPath -Name "PasswordLength" -ErrorAction SilentlyContinue
    $age = Get-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -ErrorAction SilentlyContinue
    
    Write-Host "[+] LAPS Configuration Found:" -ForegroundColor Green
    Write-Host "    - Backup Directory: $($backupDir.BackupDirectory) (1 = Active Directory)" -ForegroundColor White
    Write-Host "    - Password Complexity: $($complexity.PasswordComplexity) (4 = Maximum)" -ForegroundColor White
    Write-Host "    - Password Length: $($length.PasswordLength) characters" -ForegroundColor White
    Write-Host "    - Password Rotation Interval: $($age.PasswordAgeDays) days" -ForegroundColor White
} else {
    Write-Host "[!] VULNERABLE: Windows LAPS registry path does not exist. LAPS may not be configured." -ForegroundColor Red
}
