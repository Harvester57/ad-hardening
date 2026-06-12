# Block-RemovableStorage.ps1
# Configures local registry parameters to deny access to all removable storage classes.

Write-Host "--- Restricting Removable Storage Devices ---" -ForegroundColor Cyan

$RemovableStoragePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

if (-not (Test-Path $RemovableStoragePath)) {
    New-Item -Path $RemovableStoragePath -Force | Out-Null
}

# Deny_All = 1 blocks all removable storage classes
Set-ItemProperty -Path $RemovableStoragePath -Name "Deny_All" -Value 1 -Type DWord

Write-Host "[+] Removable storage block configured." -ForegroundColor Green
