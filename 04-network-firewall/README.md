# Module 4: Network Configuration & Firewalling

This directory contains network security architectures, active directory port configurations, and network isolation boundaries.

## Technical Hardening Controls

1. **[Configure Active Directory Port Matrix](configure-ad-port-matrix.md)**
   Establishes the minimum permitted ports for Domain Controllers, Member Servers, and Client Workstations, ensuring perimeter and local firewalls block unauthorized inbound traffic.

2. **[Restrict RPC Dynamic Ports](restrict-rpc-dynamic-ports.md)**
   Restricts default dynamic RPC ports from a massive range (TCP 49152-65535) to a predictable restricted range (e.g., TCP 50000-50100) or static ports to simplify firewall policies.

3. **[Configure Workstation and Server Isolation](configure-workstation-isolation.md)**
   Configures local firewall rules on workstations and servers to block inbound SMB, RPC, RDP, and WinRM from peer systems to prevent lateral movement.

4. **[Configure IPsec Domain Isolation](configure-ipsec-domain-isolation.md)**
   Enforces IPsec Connection Security Rules to authenticate and encrypt traffic within the domain boundary.
