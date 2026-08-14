# Configure-PawAccountSmartCardRemoval.ps1
Write-Host "Configuring PAW Smart Card removal behavior..." -ForegroundColor Cyan

$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force

Write-Host "Smart card removal behavior set to Lock Workstation." -ForegroundColor Green
