# Set-AdminPasswordPolicy.ps1
# Description: Creates a secure Fine-Grained Password Policy for administrative accounts.

Import-Module ActiveDirectory

Write-Host "Applying hardening requirement: Enforce Fine-Grained Password Policies..." -ForegroundColor Cyan

$AdminPSOName = "Tier0-Admin-PSO"
$ExistingPSO = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$AdminPSOName'"

if (-not $ExistingPSO) {
    # Create the Fine-Grained Password Policy (PSO)
    New-ADFineGrainedPasswordPolicy -Name $AdminPSOName `
        -Precedence 10 `
        -ComplexityEnabled $true `
        -MinPasswordLength 20 `
        -PasswordHistoryCount 24 `
        -ReversibleEncryptionEnabled $false `
        -LockoutDuration "00:30:00" `
        -LockoutObservationWindow "00:30:00" `
        -LockoutThreshold 5 `
        -MinPasswordAge "1.00:00:00" `
        -MaxPasswordAge "60.00:00:00"
        
    Write-Host "PSO '$AdminPSOName' created successfully." -ForegroundColor Green
} else {
    Write-Host "PSO '$AdminPSOName' already exists." -ForegroundColor Yellow
}
