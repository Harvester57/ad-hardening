# Configure-DisableIPv6DefaultDnsServers.ps1
# Description: Disables default IPv6 DNS servers in DNS Client policy on Domain Controllers.

Write-Host "Disabling default IPv6 DNS servers..." -ForegroundColor Cyan

$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path -Path $DnsClientPath)) {
    New-Item -Path $DnsClientPath -Force | Out-Null
}

Set-ItemProperty -Path $DnsClientPath -Name "DisableIPv6DefaultDnsServers" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Default IPv6 DNS servers disabled successfully (DisableIPv6DefaultDnsServers = 1)." -ForegroundColor Green
