# Get-DCNetworkHardeningStatus.ps1
# Description: Audits registry configuration of TCP/IP parameters, LLTD, Peer-to-Peer, and WCN on Domain Controllers.

Write-Host "--- Auditing Domain Controller Network Parameter Hardening ---" -ForegroundColor Cyan

# 1. Audit TCP/IP Parameters (MSS)
$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$TcpipExpected = @{
    "KeepAliveTime"             = 300000
    "PerformRouterDiscovery"    = 0
    "TcpMaxDataRetransmissions" = 3
}

if (Test-Path $TcpipParamsPath) {
    $TcpipReg = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    foreach ($K in $TcpipExpected.Keys) {
        $Val = $TcpipReg.$K
        $Exp = $TcpipExpected[$K]
        $Color = if ($Val -eq $Exp) { "Green" } else { "Red" }
        Write-Host "    - TCP/IP $($K): $($Val) (Expected: $($Exp))" -ForegroundColor $Color
    }
} else {
    Write-Host "    - TCP/IP Parameters Registry Path: NOT FOUND" -ForegroundColor Red
}

$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (Test-Path $Tcpip6ParamsPath) {
    $Tcpip6Reg = Get-ItemProperty -Path $Tcpip6ParamsPath -ErrorAction SilentlyContinue
    $Val = $Tcpip6Reg.TcpMaxDataRetransmissions
    $Color = if ($Val -eq 3) { "Green" } else { "Red" }
    Write-Host "    - TCP/IP6 TcpMaxDataRetransmissions: $($Val) (Expected: 3)" -ForegroundColor $Color
} else {
    Write-Host "    - TCP/IP6 Parameters Registry Path: NOT FOUND" -ForegroundColor Red
}

# 2. Audit IPv6 Default DNS Servers
$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (Test-Path $DnsClientPath) {
    $DnsClientReg = Get-ItemProperty -Path $DnsClientPath -ErrorAction SilentlyContinue
    $Val = $DnsClientReg.DisableIPv6DefaultDnsServers
    $Color = if ($Val -eq 1) { "Green" } else { "Red" }
    Write-Host "    - DNS Client DisableIPv6DefaultDnsServers: $($Val) (Expected: 1)" -ForegroundColor $Color
} else {
    Write-Host "    - DNS Client Registry Path: NOT FOUND" -ForegroundColor Red
}

# 3. Audit LLTD
$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
$LltdExpected = @{
    "AllowLLTDIOOnDomain"        = 0
    "AllowLLTDIOOnPublicNet"     = 0
    "EnableLLTDIO"               = 0
    "ProhibitLLTDIOOnPrivateNet" = 0
    "AllowRspndrOnDomain"        = 0
    "AllowRspndrOnPublicNet"     = 0
    "EnableRspndr"               = 0
    "ProhibitRspndrOnPrivateNet" = 0
}
if (Test-Path $LltdPath) {
    $LltdReg = Get-ItemProperty -Path $LltdPath -ErrorAction SilentlyContinue
    foreach ($K in $LltdExpected.Keys) {
        $Val = $LltdReg.$K
        $Exp = $LltdExpected[$K]
        $Color = if ($Val -eq $Exp) { "Green" } else { "Red" }
        Write-Host "    - LLTD $($K): $($Val) (Expected: $($Exp))" -ForegroundColor $Color
    }
} else {
    Write-Host "    - LLTD Registry Path: NOT FOUND" -ForegroundColor Red
}

# 4. Audit Peer-to-Peer
$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
if (Test-Path $PeernetPath) {
    $PeernetReg = Get-ItemProperty -Path $PeernetPath -ErrorAction SilentlyContinue
    $Val = $PeernetReg.Disabled
    $Color = if ($Val -eq 1) { "Green" } else { "Red" }
    Write-Host "    - Peernet Disabled: $($Val) (Expected: 1)" -ForegroundColor $Color
} else {
    Write-Host "    - Peernet Registry Path: NOT FOUND" -ForegroundColor Red
}

# 5. Audit Windows Connect Now (WCN)
$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
$WcnRegsExpected = @{
    "EnableRegistrars"               = 0
    "DisableUPnPRegistrar"           = 1
    "DisableInBand802DOT11Registrar" = 1
    "DisableFlashConfigRegistrar"    = 1
    "DisableWPDRegistrar"            = 1
}
if (Test-Path $WcnRegsPath) {
    $WcnRegsReg = Get-ItemProperty -Path $WcnRegsPath -ErrorAction SilentlyContinue
    foreach ($K in $WcnRegsExpected.Keys) {
        $Val = $WcnRegsReg.$K
        $Exp = $WcnRegsExpected[$K]
        $Color = if ($Val -eq $Exp) { "Green" } else { "Red" }
        Write-Host "    - WCN Registrars $($K): $($Val) (Expected: $($Exp))" -ForegroundColor $Color
    }
} else {
    Write-Host "    - WCN Registrars Registry Path: NOT FOUND" -ForegroundColor Red
}

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if (Test-Path $WcnUiPath) {
    $WcnUiReg = Get-ItemProperty -Path $WcnUiPath -ErrorAction SilentlyContinue
    $Val = $WcnUiReg.DisableWcnUi
    $Color = if ($Val -eq 1) { "Green" } else { "Red" }
    Write-Host "    - WCN UI DisableWcnUi: $($Val) (Expected: 1)" -ForegroundColor $Color
} else {
    Write-Host "    - WCN UI Registry Path: NOT FOUND" -ForegroundColor Red
}
