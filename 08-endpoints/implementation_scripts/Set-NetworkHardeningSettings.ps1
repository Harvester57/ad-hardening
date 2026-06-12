# Set-NetworkHardeningSettings.ps1
# Description: Configures local registry keys to disable LLMNR/NetBIOS fallbacks and harden TCP/IP stack against redirection/source routing.

Write-Host "Applying network and name resolution hardening..." -ForegroundColor Cyan

# 1. Disable LLMNR
$DnsPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $DnsPath)) {
    New-Item -Path $DnsPath -Force | Out-Null
}
Set-ItemProperty -Path $DnsPath -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "[+] LLMNR (Multicast Name Resolution) disabled." -ForegroundColor Green

# 2. Configure NetBIOS Parameters
$NetbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
if (-not (Test-Path $NetbtPath)) {
    New-Item -Path $NetbtPath -Force | Out-Null
}
Set-ItemProperty -Path $NetbtPath -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
Set-ItemProperty -Path $NetbtPath -Name "NodeType" -Value 2 -Type DWord
Write-Host "[+] NetBIOS name release protection and P-node type configured." -ForegroundColor Green

# 3. Disable NetBIOS over TCP/IP on all active adapters
Write-Host "[+] Disabling NetBIOS on all active network adapters..." -ForegroundColor Gray
$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($Adapter in $Adapters) {
    Invoke-CimMethod -InputObject $Adapter -MethodName SetTCPIPNetBIOS -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
}
Write-Host "    NetBIOS disabled on active network interfaces." -ForegroundColor Green

# 4. Harden TCP/IP Parameters
$TcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path $TcpipPath)) {
    New-Item -Path $TcpipPath -Force | Out-Null
}
Set-ItemProperty -Path $TcpipPath -Name "EnableICMPRedirect" -Value 0 -Type DWord
Set-ItemProperty -Path $TcpipPath -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Write-Host "[+] IPv4 TCP/IP parameter redirects and source routing disabled." -ForegroundColor Green

$Tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $Tcpip6Path)) {
    New-Item -Path $Tcpip6Path -Force | Out-Null
}
Set-ItemProperty -Path $Tcpip6Path -Name "DisableIPSourceRouting" -Value 2 -Type DWord
Write-Host "[+] IPv6 TCP/IP parameter source routing disabled." -ForegroundColor Green

Write-Host "Network and name resolution hardening applied successfully." -ForegroundColor Green
