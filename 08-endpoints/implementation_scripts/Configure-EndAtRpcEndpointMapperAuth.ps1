#Configure-EndAtRpcEndpointMapperAuth.ps1
# Description: Configures Administrative Templates: Enable RPC Endpoint Mapper Client Authentication.

Write-Host "Configuring Administrative Templates: Enable RPC Endpoint Mapper Client Authentication..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" -Name "EnableAuthEpResolution" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Enable RPC Endpoint Mapper Client Authentication applied successfully." -ForegroundColor Green
