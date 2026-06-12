# Hardening Requirement: Harden Network Parameters and Disable Legacy Name Resolution

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
  * **Registry Locations**:
    * HKLM\Software\Policies\Microsoft\Windows NT\DNSClient
      * `EnableMulticast` = `0` (REG_DWORD, Disables LLMNR)
    * HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters
      * `NoNameReleaseOnDemand` = `1` (REG_DWORD)
      * `NodeType` = `2` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters
      * `EnableICMPRedirect` = `0` (REG_DWORD)
      * `DisableIPSourceRouting` = `2` (REG_DWORD)
    * HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
      * `DisableIPSourceRouting` = `2` (REG_DWORD)

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

#### Step 1: Turn Off LLMNR
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO linked to the workstations OU (e.g., `GPO_Hardening_Workstations`).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\DNS Client`
4. Configure the setting:
   * **Policy**: `Turn off Multicast Name Resolution`
   * **Setting**: `Enabled`

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

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to disable legacy resolution and enforce secure TCP/IP registry parameters.

[Download Script: Set-NetworkHardeningSettings.ps1](implementation_scripts/Set-NetworkHardeningSettings.ps1)

```powershell
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
```

*To audit the network and name resolution status:*
[Download Script: Test-NetworkHardeningStatus.ps1](audit_scripts/Test-NetworkHardeningStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Benchmark**: Section 9.1 (Disable LLMNR), Section 18.8.44.1 (Configure EnableICMPRedirect), Section 18.8.44.2 (Configure DisableIPSourceRouting)
* **ANSSI AD Hardening Guide**: Recommendation R19 (LDAP and name resolution security recommendations)
