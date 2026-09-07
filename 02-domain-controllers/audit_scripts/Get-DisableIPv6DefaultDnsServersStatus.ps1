# Get-DisableIPv6DefaultDnsServersStatus.ps1
# Description: Audits registry configuration of DisableIPv6DefaultDnsServers on Domain Controllers.

Write-Host "--- Auditing DisableIPv6DefaultDnsServers Status ---" -ForegroundColor Cyan

$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$ExpectedValue = 1

if (Test-Path -Path $DnsClientPath) {
    $Reg = Get-ItemProperty -Path $DnsClientPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.DisableIPv6DefaultDnsServers

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] DisableIPv6DefaultDnsServers: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] DisableIPv6DefaultDnsServers: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] DNS Client Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
