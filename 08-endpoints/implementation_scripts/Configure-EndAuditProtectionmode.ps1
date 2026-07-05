# Configure-EndAuditProtectionmode.ps1
Write-Host "Enforcing System Mitigation control: protection-mode..." -ForegroundColor Cyan

# Set Registry value: ProtectionMode
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Value 1 -Type DWord -Force
Write-Host "    Enforced ProtectionMode = 1" -ForegroundColor Green


