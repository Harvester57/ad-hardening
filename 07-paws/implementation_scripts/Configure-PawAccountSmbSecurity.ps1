# Configure-PawAccountSmbSecurity.ps1
# Description: Configures SMB client and server security options (plaintext block, auto-disconnect, logon hours) on PAWs.

Write-Host "Configuring PAW SMB client and server security options..." -ForegroundColor Cyan

# 1. LanmanWorkstation: Block plaintext passwords
$WorkstationPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path -Path $WorkstationPath)) {
    New-Item -Path $WorkstationPath -Force | Out-Null
}
Set-ItemProperty -Path $WorkstationPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord -Force

# 2. LanmanServer: AutoDisconnect, EnableForcedLogoff, NullSessionShares
$ServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path -Path $ServerPath)) {
    New-Item -Path $ServerPath -Force | Out-Null
}
Set-ItemProperty -Path $ServerPath -Name "AutoDisconnect" -Value 15 -Type DWord -Force
Set-ItemProperty -Path $ServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ServerPath -Name "NullSessionShares" -Value @() -Type MultiString -Force

# 3. Netlogon: ForceLogoffWhenHourExpire
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path -Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $NetlogonPath -Name "ForceLogoffWhenHourExpire" -Value 1 -Type DWord -Force

Write-Host "SMB client and server security options applied successfully." -ForegroundColor Green
