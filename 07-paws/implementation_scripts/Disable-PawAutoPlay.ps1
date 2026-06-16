# Disable-PawAutoPlay.ps1
# Description: Disables AutoPlay/AutoRun registry settings globally on all drive types and non-volume devices on PAWs.

Write-Host "--- Disabling AutoPlay and AutoRun ---" -ForegroundColor Cyan

$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $ExplorerPath)) {
    New-Item -Path $ExplorerPath -Force | Out-Null
}

# NoDriveTypeAutoRun = 0xFF (255 in decimal) disables AutoRun on all types of drives
Set-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force

# NoAutorun = 1 disables AutoRun commands in inf files
Set-ItemProperty -Path $ExplorerPath -Name "NoAutorun" -Value 1 -Type DWord -Force

# Disallow Autoplay for non-volume devices (NoAutoplayfornonVolume = 1)
$PolExplorerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
if (-not (Test-Path $PolExplorerPath)) {
    New-Item -Path $PolExplorerPath -Force | Out-Null
}
Set-ItemProperty -Path $PolExplorerPath -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord -Force

Write-Host "[+] AutoPlay and AutoRun registry parameters set." -ForegroundColor Green
