# Configure-EndAccountLocalBlankPasswords.ps1
Write-Host "Configuring Endpoint local account and blank password restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) { New-Item -Path $LsaPath -Force | Out-Null }

Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ForceNetworkLogon" -Value 0 -Type DWord -Force

Write-Host "Local account and blank password restrictions applied." -ForegroundColor Green
