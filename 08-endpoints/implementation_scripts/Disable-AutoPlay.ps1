# Disable-AutoPlay.ps1
# Disables AutoPlay/AutoRun registry settings globally on all drive types.

Write-Host "--- Disabling AutoPlay and AutoRun ---" -ForegroundColor Cyan

$ExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

if (-not (Test-Path $ExplorerPath)) {
    New-Item -Path $ExplorerPath -Force | Out-Null
}

# NoDriveTypeAutoRun = 0xFF (255 in decimal) disables AutoRun on all types of drives
Set-ItemProperty -Path $ExplorerPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord

# NoAutorun = 1 disables AutoRun commands in inf files
$SystemExplorerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
Set-ItemProperty -Path $SystemExplorerPath -Name "NoAutorun" -Value 1 -Type DWord

Write-Host "[+] AutoPlay and AutoRun registry parameters set." -ForegroundColor Green
