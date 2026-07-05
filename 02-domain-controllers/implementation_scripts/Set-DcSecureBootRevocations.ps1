# Set-DcSecureBootRevocations.ps1
# Description: Triggers Secure Boot DBX and Code Integrity revocation updates for BlackLotus mitigation.

Write-Host "--- Configuring BlackLotus Secure Boot Mitigations ---" -ForegroundColor Cyan

$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
if (-not (Test-Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
}

# Trigger DBX Update (Phase 1 DBX Update = 64)
Set-ItemProperty -Path $Path -Name "AvailableUpdates" -Value 64 -Type DWord -Force | Out-Null
Write-Host "[+] BlackLotus DBX revocation update configured in registry. A system reboot is required." -ForegroundColor Green
