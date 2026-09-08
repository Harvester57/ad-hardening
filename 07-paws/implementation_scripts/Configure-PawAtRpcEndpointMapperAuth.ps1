#Configure-PawAtRpcEndpointMapperAuth.ps1
# Description: Configures Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs.

Write-Host "Configuring Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication for PAWs applied successfully." -ForegroundColor Green
