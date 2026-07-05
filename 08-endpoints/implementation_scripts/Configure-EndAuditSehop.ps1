# Configure-EndAuditSehop.ps1
Write-Host "Enforcing System Mitigation control: sehop..." -ForegroundColor Cyan

# Set Registry value: DisableExceptionChainValidation
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableExceptionChainValidation" -Value 0 -Type DWord -Force
Write-Host "    Enforced DisableExceptionChainValidation = 0" -ForegroundColor Green


