# Configure-PawAccountSmbSecurity.ps1
Write-Host "Configuring PAW SMB client and server security options..." -ForegroundColor Cyan

# 1. LanmanWorkstation
$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $LanmanWorkPath)) { New-Item -Path $LanmanWorkPath -Force | Out-Null }
Set-ItemProperty -Path $LanmanWorkPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord -Force

# 2. LanmanServer
$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $LanmanServerPath)) { New-Item -Path $LanmanServerPath -Force | Out-Null }
Set-ItemProperty -Path $LanmanServerPath -Name "AutoDisconnect" -Value 15 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -Value @() -Type MultiString -Force

# 3. Netlogon ForceLogoff
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonPath)) { New-Item -Path $NetlogonPath -Force | Out-Null }
Set-ItemProperty -Path $NetlogonPath -Name "ForceLogoffWhenHourExpire" -Value 1 -Type DWord -Force

Write-Host "SMB client and server security options applied." -ForegroundColor Green
