# Get-TcpipMaxDataRetransmissionsStatus.ps1
# Description: Audits registry configuration of TcpMaxDataRetransmissions for IPv4 and IPv6 on Domain Controllers.

Write-Host "--- Auditing TCP Max Data Retransmissions Status ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$IsVulnerable = $false

if (Test-Path -Path $TcpipParamsPath) {
    $Reg4 = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $Val4 = $Reg4.TcpMaxDataRetransmissions
    if ($Val4 -eq 3) {
        Write-Host "    [+] IPv4 TcpMaxDataRetransmissions: $($Val4) (Expected: 3)" -ForegroundColor Green
    } else {
        Write-Host "    [!] IPv4 TcpMaxDataRetransmissions: $($Val4) (Expected: 3)" -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "    [!] IPv4 Parameters Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if (Test-Path -Path $Tcpip6ParamsPath) {
    $Reg6 = Get-ItemProperty -Path $Tcpip6ParamsPath -ErrorAction SilentlyContinue
    $Val6 = $Reg6.TcpMaxDataRetransmissions
    if ($Val6 -eq 3) {
        Write-Host "    [+] IPv6 TcpMaxDataRetransmissions: $($Val6) (Expected: 3)" -ForegroundColor Green
    } else {
        Write-Host "    [!] IPv6 TcpMaxDataRetransmissions: $($Val6) (Expected: 3)" -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "    [!] IPv6 Parameters Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if ($IsVulnerable) {
    exit 1
} else {
    exit 0
}
