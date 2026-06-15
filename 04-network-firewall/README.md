# Module 4: Network Configuration & Firewalling

This directory contains network security architectures, active directory port configurations, and network isolation boundaries.

## Technical Hardening Controls

1. **[REQ-NET-001 - Configure Active Directory Port Matrix](configure-ad-port-matrix.md)**
   Establishes the minimum permitted ports for Domain Controllers, Member Servers, and Client Workstations, ensuring perimeter and local firewalls block unauthorized inbound traffic.

2. **[REQ-NET-002 - Restrict RPC Dynamic Ports](restrict-rpc-dynamic-ports.md)**
   Binds core directory services (NTDS, Netlogon, DFSR) to specific static ports to allow precise network firewall controls while maintaining the system-wide dynamic RPC port range at default values to prevent socket exhaustion.

3. **[REQ-NET-003 - Configure Workstation and Server Isolation](configure-workstation-isolation.md)**
   Configures local firewall rules on workstations and servers to block inbound SMB, RPC, RDP, and WinRM from peer systems to prevent lateral movement.

4. **[REQ-NET-004 - Configure IPsec Domain Isolation](configure-ipsec-domain-isolation.md)**
   Enforces IPsec Connection Security Rules to authenticate and encrypt traffic within the domain boundary.

5. **[REQ-NET-005 - Harden IPsec Cryptographic Configurations](harden-ipsec-cryptography.md)**
   Restricts permitted IPsec cryptography suites to secure options (AES-256 and DH Group 19/20) for Phase 1 and Phase 2 negotiations.

6. **[REQ-NET-006 - Harden TLS Protocols, Cipher Suites, and Elliptic Curves](harden-tls-configuration.md)**
   Disables legacy SSL/TLS versions, enforces TLS 1.2/1.3, orders strong cipher suites, and prioritizes secure elliptic curves.

7. **[REQ-NET-007 - Enforce SMBv3 Security and Digitally Sign/Encrypt Communications](enforce-smbv3-security.md)**
   Disables legacy SMB dialects, enforces SMBv3, and mandates message signing and encryption to protect communications and prevent relay attacks.

8. **[REQ-NET-008 - Configure Firewall Logging and Operational Settings](configure-firewall-logging.md)**
   Enforces Windows Defender Firewall state, sets default inbound block policies, disables local rule merging on Domain Controllers, and configures detailed dropped packet logging to improve security visibility and forensic capabilities.

9. **[REQ-NET-009 - Configure Hardened UNC Paths and LDAP Client Signing](configure-hardened-unc-paths.md)**
   Enforces mutual authentication and SMB signing for GPO folder structures (SYSVOL/NETLOGON), restricts workstation guest logons, and requires outgoing LDAP client signing.

10. **[REQ-NET-010 - Harden WinRM Service and Restrict Remote RPC Clients](harden-winrm-service.md)**
    Disables Basic and Digest authentication, forces encrypted WinRM communications, restricts WinRM credential caching, and blocks anonymous RPC connections.

11. **[REQ-NET-011 - Configure WMI Static Port](configure-wmi-static-port.md)**
    Binds the WMI service to static TCP port 24158 and isolates it to a standalone host process with packet privacy enabled to limit remote lateral movement exposure.

12. **[REQ-NET-012 - Configure RPC Filters for Named Pipes](configure-rpc-named-pipe-filters.md)**
    Enforces Windows Firewall RPC Filters to block administrative queries and code execution over SMB named pipes (e.g. SCM, Task Scheduler) from unauthorized subnets.

13. **[REQ-NET-013 - Block Management Traffic Between Domain Controllers](block-intra-dc-management.md)**
    Excludes Domain Controller IP addresses from allowed management rules (RDP, WinRM, WMI, ADWS) to prevent lateral movement between Tier 0 directory servers.


