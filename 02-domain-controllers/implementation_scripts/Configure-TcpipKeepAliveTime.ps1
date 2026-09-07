# Configure-TcpipKeepAliveTime.ps1
# Description: Configures TCP/IP KeepAliveTime parameter to 300000 ms (5 minutes) on Domain Controllers.

Write-Host "Configuring TCP/IP KeepAliveTime..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}

Set-ItemProperty -Path $TcpipParamsPath -Name "KeepAliveTime" -Value 300000 -Type DWord -ErrorAction Stop

Write-Host "TCP/IP KeepAliveTime configured successfully (300000 ms)." -ForegroundColor Green
