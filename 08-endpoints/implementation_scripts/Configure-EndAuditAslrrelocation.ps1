# Configure-EndAuditAslrrelocation.ps1
Write-Host "Enforcing System Mitigation control: aslr-relocation..." -ForegroundColor Cyan

# Set Registry value: MoveImages
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 4294967295 -Type DWord -Force
Write-Host "    Enforced MoveImages = 4294967295" -ForegroundColor Green


