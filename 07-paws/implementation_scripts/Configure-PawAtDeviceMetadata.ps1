#Configure-PawAtDeviceMetadata.ps1
# Description: Configures Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs.

Write-Host "Configuring Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Prevent Device Metadata Retrieval from Network for PAWs applied successfully." -ForegroundColor Green
