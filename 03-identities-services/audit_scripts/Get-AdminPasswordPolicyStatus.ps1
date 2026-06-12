# Get-AdminPasswordPolicyStatus.ps1
# Description: Audits Fine-Grained Password Policies in the Active Directory domain.

Import-Module ActiveDirectory

Write-Host "--- Auditing Fine-Grained Password Policies ---" -ForegroundColor Cyan

$psoList = Get-ADFineGrainedPasswordPolicy -Filter *

if ($psoList) {
    foreach ($pso in $psoList) {
        Write-Host "[+] PSO Name: $($pso.Name)" -ForegroundColor Green
        Write-Host "    - Precedence: $($pso.Precedence)" -ForegroundColor White
        Write-Host "    - MinPasswordLength: $($pso.MinPasswordLength)" -ForegroundColor White
        Write-Host "    - LockoutThreshold: $($pso.LockoutThreshold)" -ForegroundColor White
        Write-Host "    - LockoutDuration: $($pso.LockoutDuration)" -ForegroundColor White
    }
} else {
    Write-Host "[-] No Fine-Grained Password Policies found in the domain." -ForegroundColor Yellow
}
