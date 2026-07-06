# Test-PawNetworkHardeningStatus.ps1
# Description: Audits LLMNR, NetBIOS parameters, NetBIOS adapter state, TCP/IP parameters, and print/network connection options on PAWs.

Write-Host "--- Auditing Network and Name Resolution Baseline ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue ($path, $name, $expectedValue) {
    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    $color = "Red"
    if ($actual -eq $expectedValue) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expectedValue')" -ForegroundColor $color
}


# 1. Audit LLMNR, mDNS, and default IPv6 DNS Servers
$DnsPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
Test-RegistryValue $DnsPath "EnableMulticast" 0
Test-RegistryValue $DnsPath "EnablemDNS" 0
Test-RegistryValue $DnsPath "DisableIPv6DefaultDnsServers" 1

# 2. Audit NetBIOS Parameters
$NetbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
Test-RegistryValue $NetbtPath "NoNameReleaseOnDemand" 1
Test-RegistryValue $NetbtPath "NodeType" 2

# 3. Audit TCP/IP Parameters
$TcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Test-RegistryValue $TcpipPath "EnableICMPRedirect" 0
Test-RegistryValue $TcpipPath "DisableIPSourceRouting" 2

$Tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
Test-RegistryValue $Tcpip6Path "DisableIPSourceRouting" 2

# 4. Audit Connection Sharing & Dual-Homing Settings
$NetConnPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
Test-RegistryValue $NetConnPath "NC_ShowSharedAccessUI" 0
Test-RegistryValue $NetConnPath "NC_AllowNetBridge_NLA" 0
Test-RegistryValue $NetConnPath "NC_StdDomainUserSetLocation" 1

$WcmPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
Test-RegistryValue $WcmPath "fMinimizeConnections" 3
Test-RegistryValue $WcmPath "fBlockNonDomain" 1

$WifiPath = "HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config"
Test-RegistryValue $WifiPath "AutoConnectAllowedOEM" 0

# 5. Audit HTTP Print Options
$PrinterPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
Test-RegistryValue $PrinterPath "DisableWebPnPDownload" 1
Test-RegistryValue $PrinterPath "DisableHTTPPrinting" 1

# 6. Audit Null Session Share Restrict
$ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
Test-RegistryValue $ServerPath "RestrictNullSessAccess" 1

# 7. Audit WPAD Service and Registry Override
$WpadSvc = Get-Service -Name "WinHttpAutoProxySvc" -ErrorAction SilentlyContinue
if ($null -ne $WpadSvc) {
    if ($WpadSvc.StartType -eq "Disabled") {
        Write-Host "    - WPAD Service State: Disabled (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: WPAD Service StartType is $($WpadSvc.StartType) (Expected: Disabled)" -ForegroundColor Red
        $script:Vulnerable = $true
    }
}
$WpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
Test-RegistryValue $WpadPath "WpadOverride" 1

# 8. Audit Net Session Enumeration (NetCease)
$LanmanSecPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
if (Test-Path $LanmanSecPath) {
    $SrvsvcSessionInfo = (Get-ItemProperty -Path $LanmanSecPath -Name "SrvsvcSessionInfo" -ErrorAction SilentlyContinue).SrvsvcSessionInfo
    if ($null -ne $SrvsvcSessionInfo) {
        try {
            $SD = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $SrvsvcSessionInfo, 0)
            $Sddl = $SD.GetSddlForm("Dacl")
            if ($Sddl -eq "D:(A;;CC;;;BA)(A;;CC;;;SO)(A;;CC;;;PU)") {
                Write-Host "    - Net Session Enumeration Security Descriptor: Hardened (Secure)" -ForegroundColor Green
            } else {
                Write-Host "    - VULNERABLE: Net Session Enumeration Security Descriptor is '$Sddl' (Expected: 'D:(A;;CC;;;BA)(A;;CC;;;SO)(A;;CC;;;PU)')" -ForegroundColor Red
                $script:Vulnerable = $true
            }
        } catch {
            Write-Host "    - VULNERABLE: Failed to parse Net Session Enumeration security descriptor." -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "    - VULNERABLE: SrvsvcSessionInfo registry value not found." -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "    - VULNERABLE: LanmanServer\DefaultSecurity path not found." -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
