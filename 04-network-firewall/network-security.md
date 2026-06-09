# Module 4: Network Configuration & Firewalling

This module defines the requirements for network segregation, Windows Defender Firewall configurations, and IPsec transport encryption to secure Active Directory traffic and prevent lateral movement in air-gapped networks.

---

## 1. Active Directory Port Matrix

To restrict traffic to Domain Controllers, perimeter and local firewalls must only permit specific communication ports. All other inbound traffic to Tier 0 assets must be blocked.

| Protocol | Port | Source | Destination | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **TCP / UDP** | 53 | Clients / DCs | DCs | DNS Name Resolution |
| **UDP** | 123 | Clients / DCs | NTP Server / DCs | Network Time Protocol (Time Sync) |
| **TCP / UDP** | 88 | Clients / DCs | DCs | Kerberos Authentication |
| **TCP / UDP** | 464 | Clients | DCs | Kerberos Password Change |
| **TCP / UDP** | 389 | Clients / DCs | DCs | LDAP Directory Queries |
| **TCP** | 636 | Clients / DCs | DCs | LDAPS (LDAP over SSL/TLS) |
| **TCP** | 3268 | Clients / DCs | DCs | Global Catalog Query |
| **TCP** | 3269 | Clients / DCs | DCs | Global Catalog Query over SSL/TLS |
| **TCP** | 135 | Clients / DCs | DCs | RPC Endpoint Mapper |
| **TCP** | 445 | Clients / DCs | DCs | SMB (SYSVOL access, GPO processing) |
| **TCP** | 49152-65535 | Clients / DCs | DCs | RPC Dynamic Ports (AD Replication, DFSR) |
| **TCP** | 3389 | PAWs / Jump Hosts | DCs / Servers | Remote Desktop Protocol (RDP) |
| **TCP** | 5985 / 5986 | PAWs / Jump Hosts | DCs / Servers | WinRM (HTTP / HTTPS Administration) |

> [!TIP]
> **RPC Dynamic Port Hardening**: By default, Windows Server utilizes ports 49152-65535 for dynamic RPC. To simplify firewall rules, you can restrict this range (e.g., to 50000-50100) via the registry: `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\TCP/IP Port` or via Group Policy.

---

## 2. Workstation Isolation (Preventing Lateral Movement)

Attackers pivot laterally from workstation to workstation (Tier 2) using administrative tools (WMI, WinRM, RDP, SMB/RPC). Blocking inbound workstation-to-workstation traffic breaks the lateral movement chain.

### Workstation Isolation Rules (via GPO)
On all Tier 2 Client Workstations, Windows Defender Firewall must be configured via Group Policy to:
1. **Block all Inbound RPC** (TCP/135 and dynamic ports) from other Tier 2 IP ranges.
2. **Block all Inbound SMB** (TCP/445) from other Tier 2 IP ranges.
3. **Block all Inbound Remote Management** (RDP TCP/3389, WinRM TCP/5985-5986) from other Tier 2 IP ranges.
4. **Allow Outbound Connections** to Domain Controllers, WSUS, SIEM collectors, and management jump hosts.

---

## 3. IPsec Transport Mode for Domain Isolation (ANSSI R7)

Using IPsec Connection Security Rules ensures that communication between Domain Controllers, and optionally between clients and DCs, is authenticated and/or encrypted.

* **Requirement**: Configure IPsec Transport Mode (using Kerberos V5 or certificates for authentication) to protect:
  * **DC-to-DC Replication**: Mandate ESP encryption (Encapsulating Security Payload) to protect replication data.
  * **Client-to-DC Traffic**: Require AH (Authentication Header) or ESP (encryption) for domain-joined clients.
* This mitigates spoofing and sniffing of AD traffic, even if an attacker gains physical access to the network switch.

---

## PowerShell Implementation Guide

### 1. Auditing Network Firewall & Ports (Audit)

Run this script from a workstation or DC to verify that the local firewall is active, check active network profiles, and test connectivity to a target DC on critical ports.

```powershell
# Audit-ADNetwork.ps1
# Verifies Local Firewall status and tests connectivity to essential AD ports.

Write-Host "--- Auditing Network Security & Firewall ---" -ForegroundColor Cyan

# 1. Check Windows Defender Firewall State
$profiles = Get-NetFirewallProfile
Write-Host "`n[+] Checking Local Firewall State..." -ForegroundColor Yellow
foreach ($profile in $profiles) {
    $stateColor = if ($profile.Enabled -eq $true) { "Green" } else { "Red" }
    Write-Host "    - Profile: $($profile.Name) | Enabled: $($profile.Enabled) | DefaultInbound: $($profile.DefaultInboundAction)" -ForegroundColor $stateColor
}

# 2. Test Connection to DC on Critical Ports
# Replace $TargetDC with your Domain Controller IP or FQDN
$TargetDC = "127.0.0.1" # Defaulting to local loopback for safety in compilation check
$CriticalPorts = @(53, 88, 389, 445, 636, 3268, 3269, 5986)

Write-Host "`n[+] Testing Connectivity to DC ($TargetDC) on Critical AD Ports..." -ForegroundColor Yellow
foreach ($port in $CriticalPorts) {
    $socket = New-Object System.Net.Sockets.TcpClient
    $connect = $socket.BeginConnect($TargetDC, $port, $null, $null)
    $wait = $connect.AsyncWaitHandle.WaitOne(500, $false) # 500ms timeout
    
    if ($wait) {
        try {
            $socket.EndConnect($connect)
            Write-Host "    - Port $($port) ($([System.Net.Sockets.TcpClient]::new().ToString())): OPEN" -ForegroundColor Green
        } catch {
            Write-Host "    - Port $($port): CLOSED / BLOCKED" -ForegroundColor Yellow
        }
    } else {
         Write-Host "    - Port $($port): TIMEOUT (Blocked)" -ForegroundColor Red
    }
    $socket.Close()
}
```

### 2. Enforcing Workstation Isolation and Admin Restrictions (Remediation)

Execute the following PowerShell script on a Tier 2 workstation (or via GPO startup scripts) to configure local Windows Defender Firewall rules that block lateral traffic from peer workstations, while permitting traffic from authorized admin management ranges.

```powershell
# Set-WorkstationIsolation.ps1
# Configures local firewall rules to block inbound SMB, RPC, and RDP from peer workstations.
# Allows access only from designated Domain Controller and Admin Management Subnets.

$AdminSubnet = "10.10.0.0/24"      # Replace with your PAW / Jump Host / DC Subnet
$LocalSubnet = "10.20.0.0/16"      # Replace with your client workstation subnet

Write-Host "--- Applying Workstation Isolation Firewall Rules ---" -ForegroundColor Cyan

# 1. Enable firewall profiles
Write-Host "[+] Ensuring Windows Defender Firewall is active on all profiles..." -ForegroundColor Gray
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
Write-Host "    All firewall profiles enabled." -ForegroundColor Green

# 2. Block Inbound SMB (TCP 445) from peer workstations (LocalSubnet)
Write-Host "[+] Creating rule: Block inbound SMB (445) from Client Subnet..." -ForegroundColor Gray
New-NetFirewallRule -DisplayName "Hardening: Block Inbound SMB from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 445 `
    -RemoteAddress $LocalSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "    SMB blocking rule created." -ForegroundColor Green

# 3. Block Inbound RDP (TCP 3389) from peer workstations (LocalSubnet)
Write-Host "[+] Creating rule: Block inbound RDP (3389) from Client Subnet..." -ForegroundColor Gray
New-NetFirewallRule -DisplayName "Hardening: Block Inbound RDP from Peers" `
    -Direction Inbound `
    -Action Block `
    -Protocol TCP `
    -LocalPort 3389 `
    -RemoteAddress $LocalSubnet `
    -Profile Domain, Private `
    -Enabled True | Out-Null
Write-Host "    RDP blocking rule created." -ForegroundColor Green

# 4. Allow Inbound Administration from Management Subnet (RDP, WinRM, SMB)
Write-Host "[+] Creating rule: Allow Inbound Management from Admin Subnet..." -ForegroundColor Gray
New-NetFirewallRule -DisplayName "Hardening: Allow Admin Management Inbound" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort @(445, 3389, 5985, 5986) `
    -RemoteAddress $AdminSubnet `
    -Profile Domain `
    -Enabled True | Out-Null
Write-Host "    Management rule created." -ForegroundColor Green

Write-Host "`nWorkstation isolation firewall rules applied successfully." -ForegroundColor Cyan
```
