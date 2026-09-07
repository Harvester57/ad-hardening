# Configure TCP/IP and Network Parameter Hardening for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * `Computer Configuration\Preferences\Windows Settings\Registry` (MSS TCP/IP Parameters)
  * `Computer Configuration\Policies\Administrative Templates\Network` (DNS Client, LLTD, Peer-to-Peer, WCN)

---

## Rationale
Securing low-level TCP/IP stack parameters and network-layer discovery/advertisement protocols on Domain Controllers is essential to block local reconnaissance, rogue routing redirection, denial-of-service, and credential coercion vectors:

1. **MSS TCP/IP Parameter Tuning**: Restricting TCP data retransmissions limits the exhaustion of kernel resources during network interruption or packet floods. Disabling Internet Router Discovery Protocol (IRDP) prevents dynamic default gateway spoofing and routing redirection. Adjusting connection keep-alive timers ensures stale or disconnected sessions are promptly terminated and socket resources reclaimed.
2. **Link-Layer Topology Discovery (LLTD)**: Disabling LLTD Mapper I/O and Responder drivers prevents rogue local hosts from fingerprinting Domain Controllers, inspecting link capabilities, or generating unauthorized network topology maps.
3. **Microsoft Peer-to-Peer Networking**: Distributed peer-to-peer protocols (such as PNRP) introduce unmanaged, autonomous communication channels that circumvent centralized directory security controls and have no operational utility on Tier 0 assets.
4. **Windows Connect Now (WCN)**: Disabling WCN wireless configuration registrars (UPnP, In-Band 802.11) and graphical wizards eliminates Wi-Fi Protected Setup attack surfaces and prevents credential extraction over wireless discovery channels.
5. **Disable Default IPv6 DNS Servers**: Prevents automated fallback to unauthenticated, dynamic local IPv6 DNS servers advertised by rogue devices (e.g., via `mitm6`), mitigating name resolution redirection and authentication relay coercion.

This parent requirement coordinates the individual unitary hardening controls defined in the dedicated network hardening submodule.

---

## Legacy Impact & Compatibility
* **Network Visibility**: Disabling LLTD Mapper and Responder will prevent the Domain Controller from appearing in graphical network maps on neighboring client workstations. Core Active Directory replication, client authentication, DNS resolution, and administrative management operate unaffected.
* **Peer-to-Peer Applications**: Disabling Peernet blocks local collaboration software or home networking protocols that rely on PNRP. Such software is unsupported and prohibited on Tier 0 servers.
* **WCN Configuration**: Windows Connect Now is designed for wireless device provisioning. Because Domain Controllers operate on dedicated wired datacenter backbones, disabling WCN has zero operational impact.

---

## Network Parameter Hardening Requirements

The following unitary controls must be enforced on Domain Controllers:

1. **[REQ-DC-147 - Configure TCP/IP KeepAliveTime on Domain Controllers](network/configure-tcpip-keepalivetime.md)**
2. **[REQ-DC-148 - Disable TCP/IP Router Discovery on Domain Controllers](network/disable-tcpip-router-discovery.md)**
3. **[REQ-DC-149 - Configure TCP Max Data Retransmissions on Domain Controllers](network/configure-tcpip-max-data-retransmissions.md)**
4. **[REQ-DC-150 - Disable Default IPv6 DNS Servers on Domain Controllers](network/disable-ipv6-default-dns-servers.md)**
5. **[REQ-DC-151 - Disable Link-Layer Topology Discovery Mapper I/O Driver on Domain Controllers](network/disable-lltd-mapper-io-driver.md)**
6. **[REQ-DC-152 - Disable Link-Layer Topology Discovery Responder Driver on Domain Controllers](network/disable-lltd-responder-driver.md)**
7. **[REQ-DC-153 - Disable Microsoft Peer-to-Peer Networking Services on Domain Controllers](network/disable-peernet.md)**
8. **[REQ-DC-154 - Disable Windows Connect Now Wireless Settings Configuration on Domain Controllers](network/disable-wcn-wireless-configuration.md)**
9. **[REQ-DC-155 - Prohibit Access to Windows Connect Now Wizards on Domain Controllers](network/prohibit-wcn-wizards.md)**

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.5 (MSS Parameters), Section 18.6.4 (DNS Client), Section 18.6.9 (LLTD), Section 18.6.10 (Peer-to-Peer), Section 18.6.20 (WCN)
* **ANSSI AD Hardening Guide**: Security guidelines to disable unnecessary interfaces, protocols, and discovery mechanisms on Domain Controllers.
