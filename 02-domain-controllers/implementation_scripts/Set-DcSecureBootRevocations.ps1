# Set-DcSecureBootRevocations.ps1
# Description: Triggers Secure Boot DBX and Code Integrity revocation updates for BlackLotus mitigation.

Write-Host "--- Configuring BlackLotus Secure Boot Mitigations ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Trigger updates (0x5944 = 22852)
Set-ItemProperty -Path $Path -Name "AvailableUpdates" -Value 22852 -Type DWord -Force | Out-Null
Write-Host "[+] BlackLotus DBX and 2023 CA revocation updates configured in registry. A system reboot is required." -ForegroundColor Green
