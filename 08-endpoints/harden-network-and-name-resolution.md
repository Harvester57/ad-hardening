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
    * Computer Configuration\Administrative Templates\Network\DNS Client\Turn off default IPv6 DNS Servers
    * Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security
    * Computer Configuration\Administrative Templates\Network\Network Connections
    * Computer Configuration\Administrative Templates\Network\Windows Connection Manager
    * Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN Settings
    * Computer Configuration\Administrative Templates\Printers
    * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
    * Computer Configuration\Policies\Windows Settings\Security Settings\System Services\WinHTTP Web Proxy Auto-Discovery Service
  * **Registry Locations**:
    * HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
      * `EnableMulticast` = `0` (REG_DWORD, Disables LLMNR)
      * `EnablemDNS` = `0` (REG_DWORD, Disables mDNS)
      * `DisableIPv6DefaultDnsServers` = `1` (REG_DWORD, Turn off default IPv6 DNS Servers)
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
      * `NC_StdDomainUserSetLocation` = `1` (REG_DWORD, Require elevation to set network location)
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
    * HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad
      * `WpadOverride` = `1` (REG_DWORD, Disables WPAD)
    * HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity
      * `SrvsvcSessionInfo` = (REG_BINARY, Restricts Net Session Enumeration)

---

## Rationale
Legacy name resolution protocols and insecure default network configurations are heavily targeted by attackers for credential harvesting and man-in-the-middle (MitM) positioning:

1. **Legacy Name Resolution (LLMNR / NetBIOS)**: LLMNR and NBT-NS serve as fallback protocols when DNS resolution fails. When a host queries an unresolvable name, it broadcasts requests over the local subnet. An attacker can spoof responses (e.g., using Responder) to capture NTLMv2 hashes or perform authentication relay attacks. NetBIOS name release requests can be forged to disrupt local names unless protected.
2. **NetBIOS Node Type and Name Release**: Setting the Node Type to P-node (point-to-point, value 2) disables broadcast resolution fallbacks. Enabling name release protection (`NoNameReleaseOnDemand`) prevents attackers from spoofing name release requests to deregister local names.
3. **ICMP Redirects**: ICMP redirect packets can be used by an attacker on the same subnet to dynamically redirect routing for specific hosts through the attacker's machine, enabling full MitM packet sniffing and modification. Disabling ICMP redirects prevents this vector.
4. **IP Source Routing**: Source routing allows a sender to specify the exact network path a packet should follow. This is commonly abused to bypass firewall routing rules or establish communication paths that violate network segment isolation.
5. **Disable Default IPv6 DNS Servers**: Disabling default IPv6 DNS servers prevents automated fallback to unauthenticated, dynamic local IPv6 DNS servers advertised by rogue routers or malicious tools (like mitm6), which would otherwise redirect query traffic and coerce NTLM or Kerberos authentication.
6. **Disable Web Proxy Auto-Discovery (WPAD)**: Disabling WPAD removes another name resolution mechanism that Responder exploits to harvest credentials. By disabling the `WinHttpAutoProxySvc` service and configuring `WpadOverride = 1`, the workstation is protected from rogue web proxy configurations.
7. **Restrict Net Session Enumeration (NetCease)**: By default, any authenticated domain user can query session information from remote hosts. Attackers utilize session enumeration to locate high-privileged user sessions (e.g., Domain Admins) across the network. Hardening the `SrvsvcSessionInfo` default security descriptor blocks this remote reconnaissance.

---

## Legacy Impact & Compatibility
* **DNS Dependency**: Disabling LLMNR and NetBIOS requires a fully operational DNS infrastructure. Any internal local network resource names must be registered in the AD DNS zones. Ad-hoc name resolution (such as workgroup-based peer file sharing) will no longer function.
* **Standby Subnets**: Disabling ICMP redirects means systems will rely on static routing tables and default gateway definitions. This is the standard operational stance for secure enterprise subnets.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Configure DNS Client Settings
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO.
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\DNS Client`
4. Configure the settings:
   * **Policy**: `Turn off Multicast Name Resolution` -> **Enabled**
   * **Policy**: `Configure multicast DNS (mDNS) protocol` -> **Enabled** with option set to **Disabled**
   * **Policy**: `Turn off default IPv6 DNS Servers` -> **Enabled**

#### Step 2: Configure Network Connections Policies
1. In the target GPO, navigate to:
   `Computer Configuration\Administrative Templates\Network\Network Connections`
2. Configure the settings:
   * **Policy**: `Prohibit use of Internet Connection Sharing on your DNS domain network` -> **Enabled**
   * **Policy**: `Prohibit installation and configuration of Network Bridge on your DNS domain network` -> **Enabled**
   * **Policy**: `Require domain users to elevate when setting a network's location` -> **Enabled**

#### Step 3: Configure Windows Connection Manager Policies
1. In the target GPO, navigate to:
   `Computer Configuration\Administrative Templates\Network\Windows Connection Manager`
2. Configure the settings:
   * **Policy**: `Minimize the number of simultaneous connections to the Internet or a Windows Domain` -> **Enabled** with option set to **3 = Prevent Wi-Fi when on Ethernet**
   * **Policy**: `Prohibit connection to non-domain networks when connected to domain authenticated network` -> **Enabled**

#### Step 4: Configure WLAN Settings (WiFi Sense)
1. In the target GPO, navigate to:
   `Computer Configuration\Administrative Templates\Network\WLAN Service\WLAN Settings`
2. Configure the settings:
   * **Policy**: `Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services` -> **Disabled**

#### Step 5: Configure Spooler and HTTP Printing Policies
1. In the target GPO, navigate to:
   `Computer Configuration\Administrative Templates\System\Internet Communication Management\Internet Communication settings`
2. Configure the settings:
   * **Policy**: `Turn off downloading of print drivers over HTTP` -> **Enabled**
   * **Policy**: `Turn off printing over HTTP` -> **Enabled**

#### Step 6: Configure Network Access Security settings
1. In the target GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
2. Configure the settings:
   * **Policy**: `Network access: Restrict anonymous access to Named Pipes and Shares` -> **Enabled**

#### Step 7: Disable WinHTTP WPAD Service
1. In the target GPO, navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
2. Scroll to **WinHTTP Web Proxy Auto-Discovery Service**, select **Define this service setting**, and set the service startup mode to **Disabled**.

#### Step 8: Configure Registry Network settings via GPO Preferences
1. Under the target GPO, navigate to:
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

    * **Disable WPAD Override (User Preference)**:
      * **Action**: `Update`
      * **Hive**: `HKEY_CURRENT_USER`
      * **Key Path**: `Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad`
      * **Value Name**: `WpadOverride`
      * **Value Type**: `REG_DWORD`
      * **Value Data**: `1`

    * **Restrict Net Session Enumeration (NetCease SDDL)**:
      * **Action**: `Update`
      * **Hive**: `HKEY_LOCAL_MACHINE`
      * **Key Path**: `SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`
      * **Value Name**: `SrvsvcSessionInfo`
      * **Value Type**: `REG_BINARY`
      * **Value Data**: Generate via SDDL `D:(A;;CC;;;BA)(A;;CC;;;SO)(A;;CC;;;PU)`

#### Step 9: Disable NetBIOS (via DHCP Scope Options)
1. Open the **DHCP Management Console** (`dhcpmgmt.msc`).
2. Under Scope Options, select **Configure Options**.
3. Add **Option 043 (Vendor Specific Info)** and set the NetBIOS over TCP/IP value to `0x2` (Disable NetBIOS over TCP/IP).

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

# 1. Disable LLMNR, mDNS, and default IPv6 DNS Servers
Set-RegDWord "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
Set-RegDWord "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnablemDNS" 0
Set-RegDWord "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "DisableIPv6DefaultDnsServers" 1
Write-Host "[+] LLMNR (Multicast Name Resolution), mDNS, and default IPv6 DNS Servers disabled." -ForegroundColor Green

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
Set-RegDWord "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_StdDomainUserSetLocation" 1
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

# 8. Disable WPAD
Write-Host "[+] Disabling WinHTTP Auto-Proxy service..." -ForegroundColor Gray
Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service -Name "WinHttpAutoProxySvc" -Force -ErrorAction SilentlyContinue

$WpadPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
if (-not (Test-Path $WpadPath)) {
    New-Item -Path $WpadPath -Force | Out-Null
}
Set-ItemProperty -Path $WpadPath -Name "WpadOverride" -Value 1 -Type DWord -Force
Write-Host "[+] WPAD auto-detection disabled in user preferences registry." -ForegroundColor Green

# 9. Restrict Net Session Enumeration (NetCease SDDL)
Write-Host "[+] Restricting Net Session Enumeration..." -ForegroundColor Gray
try {
    $SD = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, "D:(A;;CC;;;BA)(A;;CC;;;SO)(A;;CC;;;PU)")
    $BinaryForm = New-Object byte[] $SD.BinaryLength
    $SD.GetBinaryForm($BinaryForm, 0)
    $LanmanSecPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
    if (-not (Test-Path $LanmanSecPath)) {
        New-Item -Path $LanmanSecPath -Force | Out-Null
    }
    Set-ItemProperty -Path $LanmanSecPath -Name "SrvsvcSessionInfo" -Value $BinaryForm -Type Binary -Force
    Write-Host "[+] Net Session Enumeration restricted to Admins/Operators/Power Users." -ForegroundColor Green
} catch {
    Write-Error "    Failed to apply Net Session Enumeration restrictions: $($_.Exception.Message)"
}

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
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 18.6.4.1 (EnablemDNS), Section 18.6.11.2 (NC_AllowNetBridge_NLA), Section 18.6.11.3 (NC_ShowSharedAccessUI), Section 18.6.11.4 (NC_StdDomainUserSetLocation), Section 18.6.21.1 & 18.6.21.2 (fMinimizeConnections & fBlockNonDomain), Section 18.6.23.2.1 (AutoConnectAllowedOEM).
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 9.1 (Disable LLMNR), Section 18.8.44.1 (Configure EnableICMPRedirect), Section 18.8.44.2 (Configure DisableIPSourceRouting).
* **ANSSI AD Hardening Guide**: Recommendation R19 (LDAP and name resolution security recommendations).
* **DoD Windows 11 Computer STIG v2r6**: Various print driver download limits, HTTP printing blocks, internet connection sharing prohibitions, hotspot connection rules, and null session restrictions.

