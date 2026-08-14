# Configure-EndAccountInteractiveLogon.ps1
Write-Host "Configuring Endpoint interactive logon security options..." -ForegroundColor Cyan

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPath)) { New-Item -Path $SystemPath -Force | Out-Null }

Set-ItemProperty -Path $SystemPath -Name "DisableCAD" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "CrashOnAuditFail" -Value 0 -Type DWord -Force

Write-Host "Interactive logon security options applied." -ForegroundColor Green
