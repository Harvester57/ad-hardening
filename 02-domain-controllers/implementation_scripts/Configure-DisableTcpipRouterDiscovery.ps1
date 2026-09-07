# Configure-DisableTcpipRouterDiscovery.ps1
# Description: Disables IRDP (PerformRouterDiscovery) on Domain Controllers.

Write-Host "Disabling TCP/IP Router Discovery..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}

Set-ItemProperty -Path $TcpipParamsPath -Name "PerformRouterDiscovery" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "TCP/IP Router Discovery disabled successfully (PerformRouterDiscovery = 0)." -ForegroundColor Green
