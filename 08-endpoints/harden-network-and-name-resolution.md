# [REQ-END-001] Harden Network Parameters and Disable Legacy Name Resolution

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Paths**:
    * Computer Configuration\Administrative Templates\Network\DNS Client\Turn off Multicast Name Resolution
    * Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security
    * Computer Configuration\Administrative Templates\Network\Network Connections
    * Computer Configuration\Administrative Templates\Network\Windows Connection Manager
    * Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN Settings
    * Computer Configuration\Administrative Templates\Printers
    * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
  * **Registry Locations**:
    * HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
      * `EnableMulticast` = `0` (REG_DWORD, Disables LLMNR)
      * `EnablemDNS` = `0` (REG_DWORD, Disables mDNS)
    * HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters
      * `NoNameReleaseOnDemand` = `1` (REG_DWORD)
      * `NodeType` = `2` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
      * `EnableICMPRedirect` = `0` (REG_DWORD)
      * `DisableIPSourceRouting` = `2` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
      * `DisableIPSourceRouting` = `2` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections
      * `NC_ShowSharedAccessUI` = `0` (REG_DWORD)
      * `NC_AllowNetBridge_NLA` = `0` (REG_DWORD, Prohibit Network Bridge)
      * `NC_StdUserAllowedToSetNetworkLocation` = `0` (REG_DWORD, Require elevation to set network location)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy
      * `fMinimizeConnections` = `3` (REG_DWORD)
      * `fBlockNonDomain` = `1` (REG_DWORD)
    * HKLM\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config
      * `AutoConnectAllowedOEM` = `0` (REG_DWORD)
    * HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers
      * `DisableWebPnPDownload` = `1` (REG_DWORD)
      * `DisableHTTPPrinting` = `1` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
      * `RestrictNullSessAccess` = `1` (REG_DWORD)

---

## Rationale
Legacy name resolution protocols and insecure default network configurations are heavily targeted by attackers for credential harvesting and man-in-the-middle (MitM) positioning:

1. **Legacy Name Resolution (LLMNR / NetBIOS)**: LLMNR and NBT-NS serve as fallback protocols when DNS resolution fails. When a host queries an unresolvable name, it broadcasts requests over the local subnet. An attacker can spoof responses (e.g., using Responder) to capture NTLMv2 hashes or perform authentication relay attacks. NetBIOS name release requests can be forged to disrupt local names unless protected.
2. **NetBIOS Node Type and Name Release**: Setting the Node Type to P-node (point-to-point, value 2) disables broadcast resolution fallbacks. Enabling name release protection (`NoNameReleaseOnDemand`) prevents attackers from spoofing name release requests to deregister local names.
3. **ICMP Redirects**: ICMP redirect packets can be used by an attacker on the same subnet to dynamically redirect routing for specific hosts through the attacker's machine, enabling full MitM packet sniffing and modification. Disabling ICMP redirects prevents this vector.
4. **IP Source Routing**: Source routing allows a sender to specify the exact network path a packet should follow. This is commonly abused to bypass firewall routing rules or establish communication paths that violate network segment isolation.

---

## Legacy Impact & Compatibility
* **DNS Dependency**: Disabling LLMNR and NetBIOS requires a fully operational DNS infrastructure. Any internal local network resource names must be registered in the AD DNS zones. Ad-hoc name resolution (such as workgroup-based peer file sharing) will no longer function.
* **Standby Subnets**: Disabling ICMP redirects means systems will rely on static routing tables and default gateway definitions. This is the standard operational stance for secure enterprise subnets.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Turn Off LLMNR and mDNS
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO.
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\DNS Client`
4. Configure the settings:
   * **Policy**: `Turn off Multicast Name Resolution` -> **Enabled**
   * **Policy**: `Configure multicast DNS (mDNS) protocol` -> **Enabled** with option set to **Disabled**

#### Step 2: Disable NetBIOS (via DHCP Scope Options)
1. Open the **DHCP Management Console** (`dhcpmgmt.msc`).
2. Under Scope Options, select **Configure Options**.
3. Add **Option 043 (Vendor Specific Info)** and set the NetBIOS over TCP/IP value to `0x2` (Disable NetBIOS over TCP/IP).

#### Step 3: Configure Registry network settings via GPO Preferences
1. Under the target workstations GPO, navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry** and select **New -> Registry Item** for each of the following:

   * **NetBIOS Name Release Protection**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Netbt\Parameters`
     * **Value Name**: `NoNameReleaseOnDemand`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `1`
     
   * **NetBIOS P-Node Type**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Netbt\Parameters`
     * **Value Name**: `NodeType`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `2`
     
   * **Disable ICMP Redirects**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
     * **Value Name**: `EnableICMPRedirect`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `0`
     
   * **Disable IP Source Routing (IPv4)**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
     * **Value Name**: `DisableIPSourceRouting`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `2`
     
   * **Disable IP Source Routing (IPv6)**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
     * **Value Name**: `DisableIPSourceRouting`
     * **Value Type**: `REG_DWORD`
      * **Value Data**: `2`

    * **Internet Connection Sharing Block**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows\Network Connections`
      * **Value Name**: `NC_ShowSharedAccessUI`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `0`

    * **Prohibit Network Bridge**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows\Network Connections`
      * **Value Name**: `NC_AllowNetBridge_NLA`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `0`

    * **Require elevation to set network location**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows\Network Connections`
      * **Value Name**: `NC_StdUserAllowedToSetNetworkLocation`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `0`

    * **Minimize Connection Count**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`
      * **Value Name**: `fMinimizeConnections`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `3`

    * **Block Non-Domain Networks**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy`
      * **Value Name**: `fBlockNonDomain`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `1`

    * **Disable Hotspot Auto-Connect**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config`
      * **Value Name**: `AutoConnectAllowedOEM`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `0`

    * **Disable Web print driver downloads**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows NT\Printers`
      * **Value Name**: `DisableWebPnPDownload`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `1`

    * **Disable HTTP printing**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SOFTWARE\Policies\Microsoft\Windows NT\Printers`
      * **Value Name**: `DisableHTTPPrinting`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `1`

    * **Restrict anonymous access to SAM and Named Pipes/Shares**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
      * **Value Name**: `RestrictNullSessAccess`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `1`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable legacy resolution and enforce secure TCP/IP registry parameters.

[Download Script: Set-NetworkHardeningSettings.ps1](implementation_scripts/Set-NetworkHardeningSettings.ps1)

```powershell
# Set-NetworkHardeningSettings.ps1
# Description: Configures local registry keys to disable LLMNR/NetBIOS, harden TCP/IP stack, prevent dual-homing, block hotspot auto-connect, print driver web downloads, HTTP printing, and limit anonymous share access.

Write-Host "Applying network and name resolution hardening..." -ForegroundColor Cyan

# Helper to configure registry keys
function Set-RegDWord {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [string]$path,
        [string]$name,
        [int]$value
    )
    if ($PSCmdlet.ShouldProcess($path, "Set registry DWORD value $name to $value")) {
        $parent = Split-Path -Path $path
        if (-not (Test-Path $parent)) {
            New-Item -Path $parent -Force | Out-Null
        }
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
    }
}

# 1. Disable LLMNR and mDNS
Set-RegDWord "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
Set-RegDWord "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnablemDNS" 0
Write-Host "[+] LLMNR (Multicast Name Resolution) and mDNS disabled." -ForegroundColor Green

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
$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled -eq $true }
if ($Adapters) {
    foreach ($Adapter in $Adapters) {
        Invoke-CimMethod -InputObject $Adapter -MethodName SetTCPIPNetBIOS -Arguments @{ TcpipNetbiosOptions = 2 } | Out-Null
    }
    Write-Host "    NetBIOS disabled on active network interfaces." -ForegroundColor Green
}

# 4. Harden TCP/IP Parameters
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" 0
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting" 2
Write-Host "[+] IPv4 TCP/IP parameter redirects and source routing disabled." -ForegroundColor Green

Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting" 2
Write-Host "[+] IPv6 TCP/IP parameter source routing disabled." -ForegroundColor Green

# 5. Prevent Network Connection Sharing and Dual-Homing Bridging
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_AllowNetBridge_NLA" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdUserAllowedToSetNetworkLocation" 0
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections" 3
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain" 1
Set-RegDWord "HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0
Write-Host "[+] Network connections, sharing, bridging, elevation, and hotspot settings configured." -ForegroundColor Green

# 6. Printing Spooler Web Downloads and HTTP printing block
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" 1
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableHTTPPrinting" 1
Write-Host "[+] Printing spooler HTTP and Web service options disabled." -ForegroundColor Green

# 7. Restrict anonymous access to SAM and Named Pipes/Shares
Set-RegDWord "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess" 1
Write-Host "[+] Anonymous null session share access restricted." -ForegroundColor Green

Write-Host "Network and name resolution hardening applied successfully." -ForegroundColor Green
```

*To audit the network and name resolution status:*
[Download Script: Test-NetworkHardeningStatus.ps1](audit_scripts/Test-NetworkHardeningStatus.ps1)

```powershell
# Test-NetworkHardeningStatus.ps1
# Description: Audits LLMNR, NetBIOS parameters, NetBIOS adapter state, TCP/IP parameters, and STIG print / network connection options.

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

# 1. Audit LLMNR and mDNS
$DnsPath = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
Test-RegistryValue $DnsPath "EnableMulticast" 0
Test-RegistryValue $DnsPath "EnablemDNS" 0

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
Test-RegistryValue $NetConnPath "NC_StdUserAllowedToSetNetworkLocation" 0

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

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 18.6.4.1 (EnablemDNS), Section 18.6.11.2 (NC_AllowNetBridge_NLA), Section 18.6.11.3 (NC_ShowSharedAccessUI), Section 18.6.11.4 (NC_StdUserAllowedToSetNetworkLocation), Section 18.6.21.1 & 18.6.21.2 (fMinimizeConnections & fBlockNonDomain), Section 18.6.23.2.1 (AutoConnectAllowedOEM).
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 9.1 (Disable LLMNR), Section 18.8.44.1 (Configure EnableICMPRedirect), Section 18.8.44.2 (Configure DisableIPSourceRouting).
* **ANSSI AD Hardening Guide**: Recommendation R19 (LDAP and name resolution security recommendations).
* **DoD Windows 11 Computer STIG v2r6**: Various print driver download limits, HTTP printing blocks, internet connection sharing prohibitions, hotspot connection rules, and null session restrictions.

