# Configure-DisableMulticastNameResolution.ps1
# Description: Disables LLMNR, NetBIOS over TCP/IP, and mDNS on all interfaces.

Write-Host "Applying hardening requirement: Disable Multicast Name Resolution..." -ForegroundColor Cyan

# 1. Disable LLMNR
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "LLMNR disabled via registry policy." -ForegroundColor Green

# 2. Disable mDNS
$mdnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
if (-not (Test-Path $mdnsPath)) {
    New-Item -Path $mdnsPath -Force | Out-Null
}
Set-ItemProperty -Path $mdnsPath -Name "EnableMDNS" -Value 0 -Type DWord
Write-Host "mDNS disabled via registry." -ForegroundColor Green

# 3. Disable NetBIOS over TCP/IP on all Network Adapters
$interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $interfacesPath) {
    $interfaces = Get-ChildItem -Path $interfacesPath
    foreach ($interface in $interfaces) {
        $intName = $interface.PSChildName
        $intPath = "$($interfacesPath)\$($intName)"
        Set-ItemProperty -Path $intPath -Name "NetbiosOptions" -Value 2 -Type DWord
        Write-Host "  NetBIOS disabled on interface: $($intName)" -ForegroundColor Gray
    }
    Write-Host "NetBIOS over TCP/IP disabled on all active interfaces." -ForegroundColor Green
} else {
    Write-Host "NetBIOS interfaces registry path not found." -ForegroundColor Yellow
}

Write-Host "Hardening applied successfully." -ForegroundColor Green
