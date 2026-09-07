# Get-TcpipKeepAliveTimeStatus.ps1
# Description: Audits registry configuration of TCP/IP KeepAliveTime on Domain Controllers.

Write-Host "--- Auditing TCP/IP KeepAliveTime ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ExpectedValue = 300000

if (Test-Path -Path $TcpipParamsPath) {
    $Reg = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.KeepAliveTime

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] KeepAliveTime: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] KeepAliveTime: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] TCP/IP Parameters Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
