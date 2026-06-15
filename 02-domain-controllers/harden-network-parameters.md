# [REQ-DC-026] Configure TCP/IP and Network Parameter Hardening for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **TCP/IP Settings (MSS)**:
    * Path: `Computer Configuration\Preferences\Windows Settings\Registry`
    * Registry Key: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
      * `KeepAliveTime` = `300000` (REG_DWORD)
      * `PerformRouterDiscovery` = `0` (REG_DWORD)
      * `TcpMaxDataRetransmissions` = `3` (REG_DWORD)
    * Registry Key: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
      * `TcpMaxDataRetransmissions` = `3` (REG_DWORD)
  * **IPv6 DNS Settings**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
      * `Turn off default IPv6 DNS Servers` -> Enabled
    * Registry Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
      * `DisableIPv6DefaultDnsServers` = `1` (REG_DWORD)
  * **Link-Layer Topology Discovery (LLTD)**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
      * `Turn on Mapper I/O (LLTDIO) driver` -> Disabled
      * `Turn on Responder (RSPNDR) driver` -> Disabled
    * Registry Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD`
      * `AllowLLTDIOOnDomain` = `0` (REG_DWORD)
      * `AllowLLTDIOOnPublicNet` = `0` (REG_DWORD)
      * `EnableLLTDIO` = `0` (REG_DWORD)
      * `ProhibitLLTDIOOnPrivateNet` = `0` (REG_DWORD)
      * `AllowRspndrOnDomain` = `0` (REG_DWORD)
      * `AllowRspndrOnPublicNet` = `0` (REG_DWORD)
      * `EnableRspndr` = `0` (REG_DWORD)
      * `ProhibitRspndrOnPrivateNet` = `0` (REG_DWORD)
  * **Peer-to-Peer Networking**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services`
      * `Turn off Microsoft Peer-to-Peer Networking Services` -> Enabled
    * Registry Key: `HKLM\SOFTWARE\Policies\Microsoft\Peernet`
      * `Disabled` = `1` (REG_DWORD)
  * **Windows Connect Now (WCN)**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
      * `Configuration of wireless settings using Windows Connect Now` -> Disabled
      * `Prohibit access of the Windows Connect Now wizards` -> Enabled
    * Registry Keys:
      * Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars`
        * `EnableRegistrars` = `0` (REG_DWORD)
        * `DisableUPnPRegistrar` = `1` (REG_DWORD)
        * `DisableInBand802DOT11Registrar` = `1` (REG_DWORD)
        * `DisableFlashConfigRegistrar` = `1` (REG_DWORD)
        * `DisableWPDRegistrar` = `1` (REG_DWORD)
      * Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI`
        * `DisableWcnUi` = `1` (REG_DWORD)

---

## Rationale
Securing low-level TCP/IP parameters and network-layer advertisement protocols on Domain Controllers is essential to block local discovery, routing redirection, and denial of service:
1. **MSS TCP/IP Tuning**: Restricting TCP data retransmissions (`TcpMaxDataRetransmissions`) limits resources allocated to unacknowledged TCP segments during connection drops, mitigating denial-of-service attempts. Disabling Internet Router Discovery Protocol (IRDP) (`PerformRouterDiscovery`) blocks gateway advertisement redirection or man-in-the-middle attacks where hosts are coerced into routing traffic through a rogue gateway. Adjusting `KeepAliveTime` optimizes connection checks.
2. **LLTD Mapper and Responder**: Disabling Link-Layer Topology Discovery (LLTD) components (`LLTDIO` and `RSPNDR`) prevents local attackers from mapping Domain Controllers on physical subnetworks or running topological discovery queries.
3. **Microsoft Peer-to-Peer and Windows Connect Now**: Peer-to-Peer protocols (PNRP) and Windows Connect Now (WCN) wizards introduce unnecessary background communication channels, local discovery broadcasts, and wireless profile exposure vectors. These services must be completely disabled on Tier 0 assets to minimize attack surface.
4. **Disable Default IPv6 DNS Servers**: Prevents automated fallback to unauthenticated, dynamic local IPv6 DNS servers advertised by third-party routers, mitigating DNS redirection or spoofing vectors.

---

## Legacy Impact & Compatibility
* **Network Discovery**: Disabling LLTD Mapper and Responder will prevent the Domain Controller from appearing in the visual "Network Map" GUI of neighboring systems. This does not affect active directory replication, client authentication, DNS resolution, or administrative connections.
* **Peer-to-Peer Applications**: Disabling Peernet blocks local administrative tools or collaboration applications that rely on Microsoft Peer-to-Peer services. These are not supported on Tier 0 servers.
* **WCN Configuration**: Windows Connect Now is designed for wireless device configuration. Since Domain Controllers must run on dedicated, wired server backbones, disabling WCN has zero operational impact.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Configure GPO templates:
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
     * **Policy**: `Turn off default IPv6 DNS Servers` -> **Enabled**
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Link-Layer Topology Discovery`
     * **Policy**: `Turn on Mapper I/O (LLTDIO) driver` -> **Disabled**
     * **Policy**: `Turn on Responder (RSPNDR) driver` -> **Disabled**
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Microsoft Peer-to-Peer Networking Services`
     * **Policy**: `Turn off Microsoft Peer-to-Peer Networking Services` -> **Enabled**
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Windows Connect Now`
     * **Policy**: `Configuration of wireless settings using Windows Connect Now` -> **Disabled**
     * **Policy**: `Prohibit access of the Windows Connect Now wizards` -> **Enabled**
4. Configure TCP/IP Registry Preferences:
   * Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
   * Create or update the following Registry Items (Right-click **Registry -> New -> Registry Item**):
     * Hive: `HKEY_LOCAL_MACHINE` | Key Path: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | Value name: `KeepAliveTime` | Value type: `REG_DWORD` | Value data: `300000`
     * Hive: `HKEY_LOCAL_MACHINE` | Key Path: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | Value name: `PerformRouterDiscovery` | Value type: `REG_DWORD` | Value data: `0`
     * Hive: `HKEY_LOCAL_MACHINE` | Key Path: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters` | Value name: `TcpMaxDataRetransmissions` | Value type: `REG_DWORD` | Value data: `3`
     * Hive: `HKEY_LOCAL_MACHINE` | Key Path: `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters` | Value name: `TcpMaxDataRetransmissions` | Value type: `REG_DWORD` | Value data: `3`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enforce network parameter hardening.

[Download Script: Configure-DCNetworkHardening.ps1](implementation_scripts/Configure-DCNetworkHardening.ps1)

```powershell
# Configure-DCNetworkHardening.ps1
# Description: Configures TCP/IP parameters, LLTD, Peer-to-Peer, and WCN hardening on Domain Controllers.

Write-Host "Applying Network Parameter Hardening..." -ForegroundColor Cyan

# 1. TCP/IP Parameters (MSS)
$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $TcpipParamsPath -Name "KeepAliveTime" -Value 300000 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $TcpipParamsPath -Name "PerformRouterDiscovery" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $TcpipParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path $Tcpip6ParamsPath)) {
    New-Item -Path $Tcpip6ParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $Tcpip6ParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

# 2. IPv6 Default DNS Servers
$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $DnsClientPath)) {
    New-Item -Path $DnsClientPath -Force | Out-Null
}
Set-ItemProperty -Path $DnsClientPath -Name "DisableIPv6DefaultDnsServers" -Value 1 -Type DWord -ErrorAction Stop

# 3. LLTD Mapper and Responder
$LltdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"
if (-not (Test-Path $LltdPath)) {
    New-Item -Path $LltdPath -Force | Out-Null
}
Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowLLTDIOOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableLLTDIO" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitLLTDIOOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnDomain" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "AllowRspndrOnPublicNet" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "EnableRspndr" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $LltdPath -Name "ProhibitRspndrOnPrivateNet" -Value 0 -Type DWord -ErrorAction Stop

# 4. Peer-to-Peer Networking
$PeernetPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
if (-not (Test-Path $PeernetPath)) {
    New-Item -Path $PeernetPath -Force | Out-Null
}
Set-ItemProperty -Path $PeernetPath -Name "Disabled" -Value 1 -Type DWord -ErrorAction Stop

# 5. Windows Connect Now (WCN)
$WcnRegsPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
if (-not (Test-Path $WcnRegsPath)) {
    New-Item -Path $WcnRegsPath -Force | Out-Null
}
Set-ItemProperty -Path $WcnRegsPath -Name "EnableRegistrars" -Value 0 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableUPnPRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableInBand802DOT11Registrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableFlashConfigRegistrar" -Value 1 -Type DWord -ErrorAction Stop
Set-ItemProperty -Path $WcnRegsPath -Name "DisableWPDRegistrar" -Value 1 -Type DWord -ErrorAction Stop

$WcnUiPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
if (-not (Test-Path $WcnUiPath)) {
    New-Item -Path $WcnUiPath -Force | Out-Null
}
Set-ItemProperty -Path $WcnUiPath -Name "DisableWcnUi" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Network parameters hardening completed successfully. A system restart is required for changes to take effect." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-DCNetworkHardeningStatus.ps1](audit_scripts/Get-DCNetworkHardeningStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.5 (MSS Parameters), Section 18.6.4 (DNS Client), Section 18.6.9 (LLTD), Section 18.6.10 (Peer-to-Peer), Section 18.6.20 (WCN)
* **ANSSI AD Hardening Guide**: Security guidelines to disable unnecessary interfaces and protocols on Domain Controllers.
