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

---

## Legacy Impact & Compatibility
* **Non-Windows and Standalone Systems**: Linux/Unix servers, network appliances, IP cameras, and network printers that do not participate in Active Directory Kerberos authentication will fail to connect. An **IPsec Boundary Group** (exemption list) must be configured to allow these hosts to communicate in cleartext.
* **Network Performance**: IPsec encryption and authentication overhead may slightly increase CPU usage on older hardware, though modern CPUs with AES-NI support experience negligible latency.
* **Deployment Sequence**: Connection Security Rules should always be set to **Request** authentication first. Once audit logs confirm all legitimate systems are successfully authenticating, the rules can be safely transitioned to **Require** authentication to prevent self-lockout.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Define IPsec Transport Rules for Domain Isolation
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting all domain assets (e.g., `GPO_Hardening_IPsec_Isolation`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Windows Defender Firewall with Advanced Security\Connection Security Rules`
4. Right-click **Connection Security Rules** and select **New Rule...**
5. Follow the Connection Security Rule Wizard:
   * **Rule Type**: `Isolation`
   * **Requirements**: `Request authentication for inbound and outbound connections` (Transition to `Require` after testing).
   * **Authentication Method**: `Computer (Kerberos V5)`
   * **Profile**: `Domain`
   * **Name**: `Hardening: IPsec Domain Isolation`

#### 2. Mandate ESP Encryption for DC-to-DC Replication
On Domain Controllers, replication traffic should be encrypted:
1. Create a GPO targeting the Domain Controllers OU.
2. Navigate to Connection Security Rules and create a new rule:
   * **Rule Type**: `Isolation`
   * **Requirements**: `Require authentication for inbound and outbound connections`
   * **Authentication Method**: `Computer (Kerberos V5)`
   * **Protocols and Ports**: Set protocol to `TCP`, local port to `49152-65535` (or your restricted RPC port, e.g., `50000-50100`).
   * **Action**: Under advanced settings, require **ESP encryption** for this connection rule.
   * **Name**: `Hardening: IPsec DC-to-DC Encryption`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and configure Connection Security Rules.

#### Remediation Script:
[Download Script: Set-IPsecDomainIsolation.ps1](implementation_scripts/Set-IPsecDomainIsolation.ps1)

```powershell
# Set-IPsecDomainIsolation.ps1
# Configures local IPsec Connection Security Rules requesting Kerberos V5 authentication.

Write-Host "Configuring IPsec Connection Security Rules..." -ForegroundColor Cyan

# Check if the rule already exists
$RuleName = "Hardening: IPsec Domain Isolation"
$ExistingRule = Get-NetIPsecRule -DisplayName $RuleName -ErrorAction SilentlyContinue

if ($null -eq $ExistingRule) {
    # Create IPsec Isolation rule requesting authentication
    New-NetIPsecRule -DisplayName $RuleName `
        -InboundSecurity Request `
        -OutboundSecurity Request `
        -Phase1AuthSet "ComputerKerberos" `
        -Enabled True | Out-Null
        
    Write-Host "IPsec Domain Isolation rule created successfully." -ForegroundColor Green
} else {
    Set-NetIPsecRule -DisplayName $RuleName -InboundSecurity Request -OutboundSecurity Request -Enabled True | Out-Null
    Write-Host "IPsec Domain Isolation rule updated/verified." -ForegroundColor Gray
}
```

#### Audit Script:
[Download Script: Test-IPsecDomainIsolation.ps1](audit_scripts/Test-IPsecDomainIsolation.ps1)

```powershell
# Test-IPsecDomainIsolation.ps1
# Checks the state of local IPsec Connection Security Rules.

Write-Host "Auditing IPsec Connection Security Rules..." -ForegroundColor Cyan

$Rules = Get-NetIPsecRule -ErrorAction SilentlyContinue

if ($null -eq $Rules -or $Rules.Count -eq 0) {
    Write-Host "    - No IPsec Connection Security Rules found (Non-Compliant)." -ForegroundColor Red
} else {
    foreach ($Rule in $Rules) {
        $Security = $Rule.InboundSecurity
        $Enabled = $Rule.Enabled
        
        $Color = "Red"
        if ($Enabled -eq $true) {
            if ($Security -eq "Request" -or $Security -eq "Require") {
                $Color = "Green"
            }
        }
        
        Write-Host "    - Rule: $($Rule.DisplayName) | Enabled: $($Enabled) | InboundSecurity: $($Security)" -ForegroundColor $Color
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R7 (IPsec transport mode for domain isolation)
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **Microsoft Security Guidance**: IPsec Domain Isolation Policies
