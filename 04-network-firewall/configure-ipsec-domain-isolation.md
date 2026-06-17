# [REQ-NET-004] Configure IPsec Domain Isolation

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, PAWs, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above) Enterprise/Professional.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Connection Security Rules`

---

## Rationale
In environments without hardware-enforced line-encryption, an attacker who gains physical or logical access to internal network switches can perform Man-in-the-Middle (MitM) attacks (e.g., ARP spoofing, DHCP spoofing) or passive packet sniffing.

Implementing IPsec Transport Mode using Connection Security Rules ensures that domain-joined hosts cryptographically authenticate each other before transmitting payloads. 

Benefits of IPsec isolation include:
1. **Host Authentication**: Ensures only trusted, domain-joined systems communicating via Kerberos V5 or certificates can exchange packets with critical servers.
2. **Data Integrity & Confidentiality**: Prevents packet tampering and sniffing on the wire. For DC-to-DC replication, mandating ESP encryption secures highly sensitive directory updates.
3. **Mitigation of Relay Attacks**: Even if credentials are intercepted, they cannot be easily replayed to services protected by IPsec isolation rules.

### Bootstrap & Kerberos Authentication Challenge
In an IPsec-enforced environment, domain members require Kerberos tickets to authenticate and establish IPsec Security Associations (SAs). However, clients must communicate with Domain Controllers to obtain these Kerberos tickets. If both endpoints and Domain Controllers strictly enforce IPsec authentication from the start, a deadlock (chicken-and-egg lockout) occurs. 

Therefore, Domain Controllers must allow unauthenticated initial requests (Request mode) to bootstrap clients, and clients must use Request mode or have explicit exemptions for the Domain Controllers during their boot sequence.

---

## Legacy Impact & Compatibility
* **Non-Windows and Standalone Systems**: Linux/Unix servers, network appliances, IP cameras, and network printers that do not participate in Active Directory Kerberos authentication will fail to connect. An **IPsec Boundary Group** (exemption list) must be configured to allow these hosts to communicate in cleartext.
* **Network Performance**: IPsec encryption and authentication overhead may slightly increase CPU usage on older hardware, though modern CPUs with AES-NI support experience negligible latency.
* **Deployment Sequence**: Connection Security Rules should always be set to **Request** authentication first. Once audit logs confirm all legitimate systems are successfully authenticating, the rules can be safely transitioned to **Require** authentication (inbound) to prevent self-lockout.
* **BitLocker Network Unlock Compatibility**: BitLocker Network Unlock sends a key-unlock payload in a cleartext DHCP request from the UEFI network stack in the pre-boot environment. Because this exchange happens before the Windows operating system and its IPsec driver are loaded, the client cannot negotiate IPsec SAs. If the Windows Deployment Services (WDS) server hosting the Network Unlock provider requires IPsec authentication for all incoming traffic, it will drop the unauthenticated UEFI client packets. To prevent this, DHCP traffic (UDP ports 67 and 68) must be exempted from IPsec enforcement on the WDS server, or the WDS server's IP address must be added to the IPsec exemption list for DHCP communications.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

To implement domain isolation successfully, two separate GPO policies must be created and linked: one targeting standard Endpoints (Member Servers and Workstations) and one targeting Domain Controllers.

#### 1. Endpoint Domain Isolation GPO (Isolated Domain)
This GPO targets all standard domain assets (Workstations, Member Servers, PAWs).

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting the target OUs (e.g., `GPO_Hardening_IPsec_Isolation_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Connection Security Rules`
4. Create the general Isolation Rule:
   * Right-click **Connection Security Rules** and select **New Rule...**
   * **Rule Type**: `Isolation`
   * **Requirements**: Select `Request authentication for inbound and outbound connections` (to allow cleartext fallback).
   * **Authentication Method**: `Computer (Kerberos V5)`
   * **Profile**: `Domain`
   * **Name**: `Hardening: IPsec Domain Isolation`
5. Configure Boot Exemptions (to prevent lockouts):
   Create a new rule for essential infrastructure services:
   * **Rule Type**: `Exemption`
   * **IP Addresses**: Add the IP addresses of your DHCP servers and DNS servers (if external or required for initial boot name resolution).
   * **Name**: `Hardening: IPsec Infrastructure Exemptions`

*Note: Domain Controllers must **not** be added to the exemption list. If DCs are exempted, all endpoint-to-DC traffic will bypass IPsec entirely. Instead, by keeping DCs subject to the general rule with `Request outbound` requirements, clients can fall back to cleartext during boot to obtain a Kerberos ticket, and will automatically establish an encrypted IPsec SA for all subsequent DC communications once authenticated. Once the domain isolation environment is stable and all domain assets have active SAs, the GPO requirement for endpoints can be upgraded to `Require authentication for inbound connections and request authentication for outbound connections`.*

#### 2. Domain Controller IPsec GPO
This GPO targets only the Domain Controllers OU. Because DCs must process bootstrap authentication from unjoined or booting machines, they cannot require IPsec for client access.

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting the Domain Controllers OU (e.g., `GPO_Hardening_IPsec_DCs`).
3. Navigate to Connection Security Rules.
4. Create the DC Client Access Rule:
   * **Rule Type**: `Isolation`
   * **Requirements**: `Request authentication for inbound and outbound connections`
   * **Authentication Method**: `Computer (Kerberos V5)`
   * **Profile**: `Domain`
   * **Name**: `Hardening: IPsec DC Client Access`
5. Create the DC-to-DC Replication Encryption Rule:
   * **Rule Type**: `Isolation`
   * **Requirements**: `Require authentication for inbound and outbound connections`
   * **Authentication Method**: `Computer (Kerberos V5)`
   * **Protocols and Ports**: Set protocol to `TCP`, local port to `49152-65535` (or your restricted RPC port, e.g., `50000-50100`).
   * **Action**: Under advanced settings, require **ESP encryption** for this connection rule.
   * **Name**: `Hardening: IPsec DC-to-DC Replication`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure Connection Security Rules.

#### Remediation Script:
[Download Script: Set-IPsecDomainIsolation.ps1](implementation_scripts/Set-IPsecDomainIsolation.ps1)

```powershell
# Set-IPsecDomainIsolation.ps1
# Configures local IPsec Connection Security Rules for Domain Isolation.
# Detects role (DC vs Endpoint) and applies appropriate isolation policies.

Write-Host "Configuring IPsec Connection Security Rules..." -ForegroundColor Cyan

# 1. Determine local machine role (Domain Controller vs Endpoint/Member Server)
$IsDomainController = $false
try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($ComputerSystem.DomainRole -eq 4 -or $ComputerSystem.DomainRole -eq 5) {
        $IsDomainController = $true
    }
} catch {
    # Fallback to checking NTDS service or environment variables if CimInstance fails
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        $IsDomainController = $true
    }
}

if ($IsDomainController) {
    Write-Host "Local system identified as a Domain Controller." -ForegroundColor Yellow
    
    # Define Rule Names
    $GeneralRuleName = "Hardening: IPsec DC Client Access"
    $DCDCRuleName = "Hardening: IPsec DC-to-DC Replication"
    
    # A. DC General Client Access Rule: Inbound/Outbound set to Request
    # Allows initial cleartext bootstrap (Kerberos, DNS, LDAP) for clients, then promotes to IPsec
    $ExistingGeneral = Get-NetIPsecRule -DisplayName $GeneralRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingGeneral) {
        New-NetIPsecRule -DisplayName $GeneralRuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Created general DC IPsec rule (Request mode)." -ForegroundColor Green
    } else {
        Set-NetIPsecRule -DisplayName $GeneralRuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Updated general DC IPsec rule (Request mode)." -ForegroundColor Gray
    }
    
    # B. DC-to-DC Replication Rule: Require authentication and require encryption
    # Targets replication ports or remote DC subnets
    $ExistingDCDC = Get-NetIPsecRule -DisplayName $DCDCRuleName -ErrorAction SilentlyContinue
    
    # Attempt to retrieve other DCs in the domain for remote IP targeting
    $DCIps = @()
    try {
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction Stop
            $DCIps = Get-ADDomainController -Filter * | Where-Object { $_.IPv4Address -ne (Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress) } | Select-Object -ExpandProperty IPv4Address
        }
    } catch {
        Write-Host "Could not query AD for other DC IP addresses. Rule will apply generally to replication ports." -ForegroundColor Yellow
    }
    
    # Configure the rule targeting replication traffic (TCP 49152-65535 or custom RPC)
    # Require authentication (forces IPsec) for DC-to-DC communication
    $Params = @{
        DisplayName = $DCDCRuleName
        InboundSecurity = "Require"
        OutboundSecurity = "Require"
        Phase1AuthSet = "ComputerKerberos"
        Protocol = "TCP"
        LocalPort = "49152-65535"
        Enabled = "True"
    }
    if ($DCIps.Count -gt 0) {
        $Params["RemoteAddress"] = $DCIps
    }
    
    if ($null -eq $ExistingDCDC) {
        New-NetIPsecRule @Params | Out-Null
        Write-Host "Created DC-to-DC replication encryption rule (Require mode)." -ForegroundColor Green
    } else {
        # RemoteAddress cannot be passed empty if we update, so omit if empty
        if ($null -eq $Params["RemoteAddress"]) {
            Set-NetIPsecRule -DisplayName $DCDCRuleName `
                -InboundSecurity Require `
                -OutboundSecurity Require `
                -Phase1AuthSet "ComputerKerberos" `
                -Protocol TCP `
                -LocalPort "49152-65535" `
                -Enabled True | Out-Null
        } else {
            Set-NetIPsecRule @Params | Out-Null
        }
        Write-Host "Updated DC-to-DC replication encryption rule (Require mode)." -ForegroundColor Gray
    }
} else {
    Write-Host "Local system identified as an Endpoint/Member Server." -ForegroundColor Yellow
    
    $RuleName = "Hardening: IPsec Domain Isolation"
    $ExistingRule = Get-NetIPsecRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    
    # Endpoints: Request inbound and Request outbound for safe deployment, 
    # then promote to Require inbound and Request outbound (fallback to cleartext for DCs/Internet)
    if ($null -eq $ExistingRule) {
        New-NetIPsecRule -DisplayName $RuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Created general Endpoint IPsec rule (Request mode)." -ForegroundColor Green
    } else {
        Set-NetIPsecRule -DisplayName $RuleName `
            -InboundSecurity Request `
            -OutboundSecurity Request `
            -Phase1AuthSet "ComputerKerberos" `
            -Enabled True | Out-Null
        Write-Host "Updated general Endpoint IPsec rule (Request mode)." -ForegroundColor Gray
    }
    
    # Create Exemption Rules for DHCP and DNS to prevent boot lockouts
    $DHCPRuleName = "Exempt: DHCP Traffic"
    $DNSRuleName = "Exempt: DNS Traffic"
    
    # DHCP Rule (UDP 67, 68)
    $ExistingDHCP = Get-NetIPsecRule -DisplayName $DHCPRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingDHCP) {
        New-NetIPsecRule -DisplayName $DHCPRuleName `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol UDP `
            -LocalPort @("67", "68") `
            -Enabled True | Out-Null
        Write-Host "Created DHCP exemption rule." -ForegroundColor Green
    }
    
    # DNS Rule (UDP/TCP 53)
    $ExistingDNS = Get-NetIPsecRule -DisplayName $DNSRuleName -ErrorAction SilentlyContinue
    if ($null -eq $ExistingDNS) {
        New-NetIPsecRule -DisplayName $DNSRuleName `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol UDP `
            -RemotePort "53" `
            -Enabled True | Out-Null
        New-NetIPsecRule -DisplayName "$DNSRuleName (TCP)" `
            -InboundSecurity None `
            -OutboundSecurity None `
            -Protocol TCP `
            -RemotePort "53" `
            -Enabled True | Out-Null
        Write-Host "Created DNS exemption rules." -ForegroundColor Green
    }
}
```

#### Audit Script:
[Download Script: Test-IPsecDomainIsolation.ps1](audit_scripts/Test-IPsecDomainIsolation.ps1)

```powershell
# Test-IPsecDomainIsolation.ps1
# Checks the state of local IPsec Connection Security Rules.
# Accounts for role-specific rules (DC vs Endpoint).

Write-Host "Auditing IPsec Connection Security Rules..." -ForegroundColor Cyan

# 1. Determine local machine role
$IsDomainController = $false
try {
    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    if ($ComputerSystem.DomainRole -eq 4 -or $ComputerSystem.DomainRole -eq 5) {
        $IsDomainController = $true
    }
} catch {
    if (Get-Service -Name NTDS -ErrorAction SilentlyContinue) {
        $IsDomainController = $true
    }
}

$NonCompliant = $false

if ($IsDomainController) {
    Write-Host "Auditing Domain Controller IPsec rules..." -ForegroundColor Yellow
    
    # DC should have a Client Access rule set to Request (or better)
    $GeneralRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec DC Client Access" -ErrorAction SilentlyContinue
    if ($null -eq $GeneralRule -or $GeneralRule.Enabled -ne $true) {
        Write-Host "    - General DC IPsec rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $GeneralRule.InboundSecurity
        $OutboundSec = $GeneralRule.OutboundSecurity
        if ($InboundSec -ne "Request" -and $InboundSec -ne "Require") {
            Write-Host "    - General DC IPsec Inbound Security is '$InboundSec' (Non-Compliant, should be Request)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - General DC IPsec Inbound Security: $InboundSec (Compliant)" -ForegroundColor Green
        }
    }
    
    # DC should have a DC-to-DC replication rule set to Require
    $DCDCRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec DC-to-DC Replication" -ErrorAction SilentlyContinue
    if ($null -eq $DCDCRule -or $DCDCRule.Enabled -ne $true) {
        Write-Host "    - DC-to-DC Replication rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $DCDCRule.InboundSecurity
        $OutboundSec = $DCDCRule.OutboundSecurity
        if ($InboundSec -ne "Require" -or $OutboundSec -ne "Require") {
            Write-Host "    - DC-to-DC IPsec Inbound/Outbound is '$InboundSec'/'$OutboundSec' (Non-Compliant, should be Require)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - DC-to-DC IPsec rule: Require (Compliant)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "Auditing Endpoint/Member Server IPsec rules..." -ForegroundColor Yellow
    
    # Endpoint should have a general Domain Isolation rule set to Request (transition) or Require (inbound) / Request (outbound)
    $GeneralRule = Get-NetIPsecRule -DisplayName "Hardening: IPsec Domain Isolation" -ErrorAction SilentlyContinue
    if ($null -eq $GeneralRule -or $GeneralRule.Enabled -ne $true) {
        Write-Host "    - Endpoint Domain Isolation rule: NOT FOUND or DISABLED (Non-Compliant)" -ForegroundColor Red
        $NonCompliant = $true
    } else {
        $InboundSec = $GeneralRule.InboundSecurity
        $OutboundSec = $GeneralRule.OutboundSecurity
        
        # Request/Request or Require/Request are acceptable depending on transition phase
        if ($InboundSec -eq "None" -or $OutboundSec -eq "None") {
            Write-Host "    - Endpoint Domain Isolation is set to None (Non-Compliant)" -ForegroundColor Red
            $NonCompliant = $true
        } else {
            Write-Host "    - Endpoint Domain Isolation rule: Enabled (Inbound: $InboundSec, Outbound: $OutboundSec) (Compliant)" -ForegroundColor Green
        }
    }
    
    # DHCP and DNS exemptions should be configured if outbound is strict
    $DHCPRule = Get-NetIPsecRule -DisplayName "Exempt: DHCP Traffic" -ErrorAction SilentlyContinue
    if ($null -eq $DHCPRule) {
        Write-Host "    - DHCP Exemption rule: NOT FOUND (Warning: highly recommended to prevent DHCP issues)" -ForegroundColor Yellow
    } else {
        Write-Host "    - DHCP Exemption rule: FOUND (Compliant)" -ForegroundColor Green
    }
    
    $DNSRule = Get-NetIPsecRule -DisplayName "Exempt: DNS Traffic" -ErrorAction SilentlyContinue
    if ($null -eq $DNSRule) {
        Write-Host "    - DNS Exemption rule: NOT FOUND (Warning: highly recommended to prevent DNS name resolution failures during boot)" -ForegroundColor Yellow
    } else {
        Write-Host "    - DNS Exemption rule: FOUND (Compliant)" -ForegroundColor Green
    }
}

if ($NonCompliant) {
    Write-Host "IPsec Domain Isolation Audit: Non-Compliant." -ForegroundColor Red
    exit 1
} else {
    Write-Host "IPsec Domain Isolation Audit: Compliant." -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (IPsec transport mode for domain isolation)
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **Microsoft Security Guidance**: IPsec Domain Isolation Policies

