# Test-RemovableStorage.ps1
# Audits registry values for removable storage blocks.

Write-Host "--- Auditing Removable Storage Restrictions ---" -ForegroundColor Cyan

$RemovableStoragePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"

$DenyAllProp = Get-ItemProperty -Path $RemovableStoragePath -Name "Deny_All" -ErrorAction SilentlyContinue
$DenyAllVal = if ($DenyAllProp) { $DenyAllProp.Deny_All } else { 0 }
$DenyColor = if ($DenyAllVal -eq 1) { "Green" } else { "Red" }

Write-Host "    - Removable Storage Deny_All: $DenyAllVal (Required = 1)" -ForegroundColor $DenyColor
