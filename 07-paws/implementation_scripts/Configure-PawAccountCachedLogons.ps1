# Configure-PawAccountCachedLogons.ps1
Write-Host "Configuring PAW cached logon restrictions and PBKDF2 iterations..." -ForegroundColor Cyan

# 1. Disable cached logons count
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -Value 0 -Type DWord -Force

# 2. Configure PBKDF2 Iteration Count
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path $CachePath)) { New-Item -Path $CachePath -Force | Out-Null }
Set-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -Value 1954 -Type DWord -Force

Write-Host "Cached logons count disabled and PBKDF2 iteration count configured." -ForegroundColor Green
