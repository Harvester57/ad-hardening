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

5. **[Harden IPsec Cryptographic Configurations](harden-ipsec-cryptography.md)**
   Restricts permitted IPsec cryptography suites to secure options (AES-256 and DH Group 19/20) for Phase 1 and Phase 2 negotiations.

6. **[Harden TLS Protocols, Cipher Suites, and Elliptic Curves](harden-tls-configuration.md)**
   Disables legacy SSL/TLS versions, enforces TLS 1.2/1.3, orders strong cipher suites, and prioritizes secure elliptic curves.

7. **[Enforce SMBv3 Security and Digitally Sign/Encrypt Communications](enforce-smbv3-security.md)**
   Disables legacy SMB dialects, enforces SMBv3, and mandates message signing and encryption to protect communications and prevent relay attacks.

8. **[Configure Firewall Logging and Operational Settings](configure-firewall-logging.md)**
   Enforces Windows Defender Firewall state, sets default inbound block policies, disables local rule merging on Domain Controllers, and configures detailed dropped packet logging to improve security visibility and forensic capabilities.

9. **[Configure Hardened UNC Paths](configure-hardened-unc-paths.md)**
   Enforces mutual authentication and SMB signing for GPO folder structures (SYSVOL/NETLOGON), restricts workstation guest logons, and requires outgoing LDAP client signing.

10. **[Harden WinRM Service and Restrict RPC Clients](harden-winrm-service.md)**
    Disables Basic and Digest authentication, forces encrypted WinRM communications, restricts WinRM credential caching, and blocks anonymous RPC connections.

