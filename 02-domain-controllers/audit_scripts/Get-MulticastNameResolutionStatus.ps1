# Get-MulticastNameResolutionStatus.ps1
# Description: Audits LLMNR, NetBIOS, and mDNS registry settings.

Write-Host "--- Auditing Multicast Name Resolution ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit LLMNR
$llmnrReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($llmnrReg) {
    if ($llmnrReg.EnableMulticast -eq 1) {
        Write-Host "[!] VULNERABLE: LLMNR is explicitly enabled." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] LLMNR is disabled." -ForegroundColor Green
    }
} else {
    Write-Host "[!] VULNERABLE: LLMNR policy key 'EnableMulticast' does not exist (default is enabled)." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit mDNS
$mdnsReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -ErrorAction SilentlyContinue
if ($mdnsReg) {
    if ($mdnsReg.EnableMDNS -ne 0) {
        Write-Host "[!] VULNERABLE: mDNS is enabled." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] mDNS is disabled." -ForegroundColor Green
    }
} else {
    # Default is enabled on Windows Server 2022 / Windows 11
    Write-Host "[!] VULNERABLE: mDNS key 'EnableMDNS' is missing (default is enabled)." -ForegroundColor Red
    $vulnerable = $true
}

# 3. Audit NetBIOS over TCP/IP
$interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $interfacesPath) {
    $interfaces = Get-ChildItem -Path $interfacesPath
    $netbiosEnabledCount = 0
    foreach ($interface in $interfaces) {
        $intName = $interface.PSChildName
        $intPath = "$($interfacesPath)\$($intName)"
        $optVal = Get-ItemProperty -Path $intPath -Name "NetbiosOptions" -ErrorAction SilentlyContinue
        if ($optVal) {
            if ($optVal.NetbiosOptions -ne 2) {
                Write-Host "[!] VULNERABLE: NetBIOS is enabled/default on interface: $($intName) (NetbiosOptions = $($optVal.NetbiosOptions))" -ForegroundColor Red
                $netbiosEnabledCount = $netbiosEnabledCount + 1
            }
        } else {
            Write-Host "[!] VULNERABLE: NetbiosOptions value missing (default enabled) on interface: $($intName)" -ForegroundColor Red
            $netbiosEnabledCount = $netbiosEnabledCount + 1
        }
    }
    
    if ($netbiosEnabledCount -gt 0) {
        Write-Host "[!] VULNERABLE: NetBIOS over TCP/IP is active on $($netbiosEnabledCount) interface(s)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] NetBIOS over TCP/IP is disabled on all interfaces." -ForegroundColor Green
    }
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
