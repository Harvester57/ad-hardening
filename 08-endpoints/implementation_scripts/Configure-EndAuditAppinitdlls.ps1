# Configure-EndAuditAppinitdlls.ps1
Write-Host "Enforcing System Mitigation control: appinit-dlls..." -ForegroundColor Cyan

# Set Registry value: LoadAppInit_DLLs
if (-not (Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows")) { New-Item -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Force | Out-Null }
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -Value 0 -Type DWord -Force
Write-Host "    Enforced LoadAppInit_DLLs = 0" -ForegroundColor Green


