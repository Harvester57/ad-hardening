# Get-TcpipRouterDiscoveryStatus.ps1
# Description: Audits registry configuration of PerformRouterDiscovery on Domain Controllers.

Write-Host "--- Auditing TCP/IP Router Discovery Status ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ExpectedValue = 0

if (Test-Path -Path $TcpipParamsPath) {
    $Reg = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.PerformRouterDiscovery

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] PerformRouterDiscovery: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] PerformRouterDiscovery: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] TCP/IP Parameters Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
