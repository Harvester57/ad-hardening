# Configure-EndAuditGamedvr.ps1
Write-Host "Enforcing System Mitigation control: game-dvr..." -ForegroundColor Cyan

# Set Registry value: AllowGameDVR
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Value 0 -Type DWord -Force
Write-Host "    Enforced AllowGameDVR = 0" -ForegroundColor Green


