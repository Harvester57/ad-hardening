# Get-LAPSStatus.ps1
# Description: Checks the Windows LAPS registry parameters.

Write-Host "--- Auditing LAPS Registry Configuration ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"

if (Test-Path $RegPath) {
    $enableLAPS = Get-ItemProperty -Path $RegPath -Name "EnableLAPS" -ErrorAction SilentlyContinue
    $backupDir = Get-ItemProperty -Path $RegPath -Name "BackupDirectory" -ErrorAction SilentlyContinue
    $expirationProtection = Get-ItemProperty -Path $RegPath -Name "PasswordExpirationProtectionEnabled" -ErrorAction SilentlyContinue
    $encryption = Get-ItemProperty -Path $RegPath -Name "ADPasswordEncryptionEnabled" -ErrorAction SilentlyContinue
    $complexity = Get-ItemProperty -Path $RegPath -Name "PasswordComplexity" -ErrorAction SilentlyContinue
    $length = Get-ItemProperty -Path $RegPath -Name "PasswordLength" -ErrorAction SilentlyContinue
    $age = Get-ItemProperty -Path $RegPath -Name "PasswordAgeDays" -ErrorAction SilentlyContinue
    $resetDelay = Get-ItemProperty -Path $RegPath -Name "PostAuthenticationResetDelay" -ErrorAction SilentlyContinue
    $actions = Get-ItemProperty -Path $RegPath -Name "PostAuthenticationActions" -ErrorAction SilentlyContinue
    
    Write-Host "[+] LAPS Configuration Found under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -ForegroundColor Green
    
    # Audit EnableLAPS
    if ($null -ne $enableLAPS -and $enableLAPS.EnableLAPS -eq 1) {
        Write-Host "    - LAPS Management: Enabled" -ForegroundColor White
    } else {
        Write-Host "    - LAPS Management: NOT ENABLED (EnableLAPS = 0 or missing)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit BackupDirectory
    if ($null -ne $backupDir -and $backupDir.BackupDirectory -eq 2) {
        Write-Host "    - Backup Directory: $($backupDir.BackupDirectory) (2 = Active Directory)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $backupDir) { $val = $backupDir.BackupDirectory }
        Write-Host "    - Backup Directory: $($val) (Expected: 2 = Active Directory)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Expiration Protection
    if ($null -ne $expirationProtection -and $expirationProtection.PasswordExpirationProtectionEnabled -eq 1) {
        Write-Host "    - Expiration Protection: Enabled" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $expirationProtection) { $val = $expirationProtection.PasswordExpirationProtectionEnabled }
        Write-Host "    - Expiration Protection: $($val) (Expected: 1)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Encryption
    if ($null -ne $encryption -and $encryption.ADPasswordEncryptionEnabled -eq 1) {
        Write-Host "    - Password Encryption: Enabled" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $encryption) { $val = $encryption.ADPasswordEncryptionEnabled }
        Write-Host "    - Password Encryption: $($val) (Expected: 1)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Complexity
    if ($null -ne $complexity -and $complexity.PasswordComplexity -eq 4) {
        Write-Host "    - Password Complexity: $($complexity.PasswordComplexity) (4 = Large + small + numbers + special characters)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $complexity) { $val = $complexity.PasswordComplexity }
        Write-Host "    - Password Complexity: $($val) (Expected: 4)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Length
    if ($null -ne $length -and $length.PasswordLength -ge 15) {
        Write-Host "    - Password Length: $($length.PasswordLength) characters (Secure, >= 15)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $length) { $val = $length.PasswordLength }
        Write-Host "    - Password Length: $($val) (Expected: >= 15)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Age
    if ($null -ne $age -and $age.PasswordAgeDays -le 30) {
        Write-Host "    - Password Rotation Interval: $($age.PasswordAgeDays) days (Secure, <= 30)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $age) { $val = $age.PasswordAgeDays }
        Write-Host "    - Password Rotation Interval: $($val) (Expected: <= 30)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Post-Authentication Reset Delay
    if ($null -ne $resetDelay -and $resetDelay.PostAuthenticationResetDelay -le 8 -and $resetDelay.PostAuthenticationResetDelay -gt 0) {
        Write-Host "    - Post-Auth Reset Delay: $($resetDelay.PostAuthenticationResetDelay) hours (Secure, <= 8)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $resetDelay) { $val = $resetDelay.PostAuthenticationResetDelay }
        Write-Host "    - Post-Auth Reset Delay: $($val) (Expected: <= 8 and > 0)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
    # Audit Post-Authentication Actions
    if ($null -ne $actions -and $actions.PostAuthenticationActions -eq 3) {
        Write-Host "    - Post-Auth Actions: $($actions.PostAuthenticationActions) (3 = Reset and logoff)" -ForegroundColor White
    } else {
        $val = "Missing"
        if ($null -ne $actions) { $val = $actions.PostAuthenticationActions }
        Write-Host "    - Post-Auth Actions: $($val) (Expected: 3 = Reset and logoff)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
    
} else {
    Write-Host "[!] VULNERABLE: Windows LAPS registry path does not exist. LAPS is not configured." -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
