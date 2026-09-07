# Configure-TcpipMaxDataRetransmissions.ps1
# Description: Sets TcpMaxDataRetransmissions to 3 for IPv4 and IPv6 on Domain Controllers.

Write-Host "Configuring TCP Max Data Retransmissions (IPv4 and IPv6)..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $TcpipParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path -Path $Tcpip6ParamsPath)) {
    New-Item -Path $Tcpip6ParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $Tcpip6ParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

Write-Host "TCP Max Data Retransmissions configured to 3 for IPv4 and IPv6." -ForegroundColor Green
