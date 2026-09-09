# [REQ-END-181] Administrative Templates: MSS IP Source Routing and ICMP Redirects

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-170](../../07-paws/admin-templates/configure-paw-at-mss-ip-source-routing.md); for Domain Controllers, refer to [REQ-DC-018](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **IPv6 IP Source Routing Protection**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level` -> **Enabled** (Value: `Highest protection, source routing is completely disabled`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
    * Value Name: `DisableIPSourceRouting`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Highest protection)
  * **IPv4 IP Source Routing Protection**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (DisableIPSourceRouting) IP source routing protection level` -> **Enabled** (Value: `Highest protection, source routing is completely disabled`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * Value Name: `DisableIPSourceRouting`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Highest protection)
  * **Disable ICMP Redirect Processing**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes` -> **Disabled**
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * Value Name: `EnableICMPRedirect`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Ignore ICMP redirects)

---

## Rationale
The Internet Protocol suite (IPv4 RFC 791 and IPv6 RFC 2460/8200) contains legacy diagnostic and routing mechanisms that allow packet senders and adjacent network nodes to manipulate routing decisions. In hostile or untrusted network environments, these capabilities introduce critical exposure to packet spoofing, firewall evasion, and adversary-in-the-middle attacks.

### 1. IP Source Routing Exploitation Vectors
IP Source Routing (both Strict and Loose Source and Record Route options in IPv4, and Routing Header Type 0 in IPv6) permits the originating sender to embed a sequence of intermediate IP hops directly within the packet header, overriding standard autonomous system and router path decisions:
* **Perimeter Firewall and Boundary Filter Bypasses**: Attackers can specify trusted intermediate transit routers to guide unauthorized packets across network boundaries or through packet-filtering gateways that would normally drop external traffic.
* **Blind TCP Spoofing and Session Injection**: When source routing is enabled, an external attacker who cannot see legitimate two-way traffic can forge the source IP of a trusted internal machine and designate an attacker-controlled intermediary router as a return hop. The victim endpoint obeys the reverse source route, returning SYN-ACK and payload responses directly to the attacker, completing the TCP handshake and enabling unauthorized command injection.
* **IPv6 Routing Header Type 0 Amplification Attacks**: In IPv6, maliciously constructed RH0 headers allow packets to loop between nodes repeatedly, causing network bandwidth exhaustion and CPU denial of service (CVE-2007-2242 / RFC 5095).
* Setting `DisableIPSourceRouting = 2` enforces the highest protection level on both IPv4 and IPv6 stacks, instructing the Windows kernel to unconditionally drop all packets containing source route options.

### 2. ICMP Redirect (Type 5) Route Hijacking
ICMP Redirect messages are designed to notify hosts when an alternate local gateway provides a shorter path to a specific destination network. However, ICMP redirect packets lack cryptographic authentication:
* **Route Table Poisoning**: An unauthenticated attacker situated on the same local subnet can transmit spoofed ICMP Type 5 Redirect frames claiming to be the default gateway.
* **Adversary-in-the-Middle (AiTM) Positioning**: The victim endpoint's IP stack dynamically inserts the attacker's chosen gateway into its route table cache. Outbound connections destined for critical resources (such as Domain Controllers, authentication proxies, or intranet servers) are redirected through the attacker's host.
* Setting `EnableICMPRedirect = 0` completely disables the processing of ICMP Redirect messages, guaranteeing that the endpoint's routing table cannot be altered by unauthenticated network packets.

### 3. MITRE ATT&CK Mapping
* **T1557 - Adversary-in-the-Middle**: Route hijacking via forged ICMP redirect messages to inspect or alter transit traffic.
* **T1565.002 - Data Manipulation: Transmitted Data Manipulation**: Manipulating packet delivery paths to intercept sensitive communications.
* **T1498 - Network Denial of Service**: Generating artificial routing loops or blackholing network traffic via forged routing headers.

---

## Legacy Impact & Compatibility
* **Production Enterprise Networks**: Standard corporate networks manage routing exclusively at the layer-3 switch and router tier using dynamic protocols (OSPF, BGP) or First Hop Redundancy Protocols (HSRP, VRRP). Client endpoints and member servers have no legitimate requirement to process ICMP redirects or execute source-routed packets.
* **Network Diagnostics**: Specialized legacy diagnostic tools that explicitly craft source-routed probe packets will fail to elicit responses from hardened endpoints. Standard diagnostics (`ping`, `traceroute`, `pathping`) function normally without issue.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (DisableIPSourceRouting IPv6) IP source routing protection level**: Set to `Enabled`
  * Select drop-down value: `Highest protection, source routing is completely disabled`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (DisableIPSourceRouting) IP source routing protection level**: Set to `Enabled`
  * Select drop-down value: `Highest protection, source routing is completely disabled`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit and verify replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtMssIpSourceRouting.ps1](../implementation_scripts/Configure-EndAtMssIpSourceRouting.ps1)

```powershell
#Configure-EndAtMssIpSourceRouting.ps1
# Description: Configures Administrative Templates: MSS IP Source Routing and ICMP Redirects.

Write-Host "Configuring Administrative Templates: MSS IP Source Routing and ICMP Redirects..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: MSS IP Source Routing and ICMP Redirects applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtMssIpSourceRoutingStatus.ps1](../audit_scripts/Get-EndAtMssIpSourceRoutingStatus.ps1)

```powershell
#Get-EndAtMssIpSourceRoutingStatus.ps1
# Description: Audits Administrative Templates: MSS IP Source Routing and ICMP Redirects.

Write-Host "--- Auditing Administrative Templates: MSS IP Source Routing and ICMP Redirects ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ValueName = "DisableIPSourceRouting"
$ExpectedValue = 2
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ValueName = "DisableIPSourceRouting"
$ExpectedValue = 2
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ValueName = "EnableICMPRedirect"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.5.8, Section 18.5.9, Section 18.5.10; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.5.8, Section 18.5.9, Section 18.5.10
* **DISA STIG**: Windows 10 STIG Rules WN10-SO-000185, WN10-SO-000190, WN10-SO-000195
* **ANSSI Active Directory Hardening Guide**: Section 3.2.4 (TCP/IP Stack Hardening on Managed Nodes)
* **Microsoft Security Baseline**: MSS (Microsoft Security Compliance Toolkit) Parameter Baseline
* **IETF RFCs**: RFC 791 (Internet Protocol), RFC 5095 (Deprecation of Type 0 Routing Headers in IPv6)
