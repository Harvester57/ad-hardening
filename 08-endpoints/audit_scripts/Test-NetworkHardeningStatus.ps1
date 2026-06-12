# Test-NetworkHardeningStatus.ps1
# Description: Audits LLMNR, NetBIOS parameters, NetBIOS adapter state, and TCP/IP security parameters.

Write-Host "--- Auditing Network and Name Resolution Baseline ---" -ForegroundColor Cyan

# 1. Audit LLMNR
$DnsPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
$LlmnrVal = Get-ItemProperty -Path $DnsPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
$LlmnrSetting = if ($LlmnrVal) { $LlmnrVal.EnableMulticast } else { 1 }
$LlmnrColor = if ($LlmnrSetting -eq 0) { "Green" } else { "Red" }
Write-Host "    - LLMNR Enabled: $LlmnrSetting (Required = 0 [Disabled])" -ForegroundColor $LlmnrColor

# 2. Audit NetBIOS Parameters
$NetbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
$NoRelease = Get-ItemProperty -Path $NetbtPath -Name "NoNameReleaseOnDemand" -ErrorAction SilentlyContinue
$Node = Get-ItemProperty -Path $NetbtPath -Name "NodeType" -ErrorAction SilentlyContinue

$NoReleaseVal = if ($NoRelease) { $NoRelease.NoNameReleaseOnDemand } else { 0 }
$NodeVal = if ($Node) { $Node.NodeType } else { 0 }

$NoReleaseColor = if ($NoReleaseVal -eq 1) { "Green" } else { "Red" }
$NodeColor = if ($NodeVal -eq 2) { "Green" } else { "Red" }

Write-Host "    - NetBIOS NoNameReleaseOnDemand: $NoReleaseVal (Required = 1)" -ForegroundColor $NoReleaseColor
Write-Host "    - NetBIOS NodeType (P-Node): $NodeVal (Required = 2)" -ForegroundColor $NodeColor

# 3. Audit TCP/IP Parameters
$TcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$Icmp = Get-ItemProperty -Path $TcpipPath -Name "EnableICMPRedirect" -ErrorAction SilentlyContinue
$RoutingV4 = Get-ItemProperty -Path $TcpipPath -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue

$IcmpVal = if ($Icmp) { $Icmp.EnableICMPRedirect } else { 1 }
$RoutingV4Val = if ($RoutingV4) { $RoutingV4.DisableIPSourceRouting } else { 0 }

$IcmpColor = if ($IcmpVal -eq 0) { "Green" } else { "Red" }
$RoutingV4Color = if ($RoutingV4Val -eq 2) { "Green" } else { "Red" }

Write-Host "    - IPv4 EnableICMPRedirect: $IcmpVal (Required = 0)" -ForegroundColor $IcmpColor
Write-Host "    - IPv4 DisableIPSourceRouting: $RoutingV4Val (Required = 2)" -ForegroundColor $RoutingV4Color

$Tcpip6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$RoutingV6 = Get-ItemProperty -Path $Tcpip6Path -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue
$RoutingV6Val = if ($RoutingV6) { $RoutingV6.DisableIPSourceRouting } else { 0 }
$RoutingV6Color = if ($RoutingV6Val -eq 2) { "Green" } else { "Red" }

Write-Host "    - IPv6 DisableIPSourceRouting: $RoutingV6Val (Required = 2)" -ForegroundColor $RoutingV6Color
