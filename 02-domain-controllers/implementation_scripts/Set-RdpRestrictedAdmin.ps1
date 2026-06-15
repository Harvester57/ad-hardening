# Set-RdpRestrictedAdmin.ps1
# Description: Enables RDP Restricted Admin mode support and hardens RDP session options.

Write-Host "Applying hardening requirement: Enforce RDP Restricted Admin Mode and Session Controls..." -ForegroundColor Cyan

# 1. Enable Restricted Admin support
$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$ValueName = "DisableRestrictedAdmin"
$ValueData = 0

if (Test-Path $LsaPath) {
    Set-ItemProperty -Path $LsaPath -Name $ValueName -Value $ValueData -Type DWord -ErrorAction Stop
    Write-Host "[+] Local system configured to accept RDP Restricted Admin connections." -ForegroundColor Green
} else {
    Write-Warning "LSA Registry path not found."
}

# 2. Harden RDP Session options in registry
$RdpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $RdpPolicyPath)) {
    New-Item -Path $RdpPolicyPath -Force | Out-Null
}

$RdpSettings = @{
    "DisablePasswordSaving" = 1
    "fSingleSessionPerUser" = 1
    "fDisableCdm"           = 1
    "fDisableCcm"           = 1
    "fDisableLpt"           = 1
    "fDisablePNPRedir"      = 1
    "fPromptForPassword"    = 1
    "fEncryptRPCTraffic"    = 1
    "MinEncryptionLevel"    = 3
    "MaxIdleTime"           = 900000
    "MaxDisconnectionTime"  = 60000
}

foreach ($Setting in $RdpSettings.Keys) {
    Set-ItemProperty -Path $RdpPolicyPath -Name $Setting -Value $RdpSettings[$Setting] -Type DWord -ErrorAction Stop
}
Write-Host "[+] RDP session security controls applied to registry." -ForegroundColor Green
