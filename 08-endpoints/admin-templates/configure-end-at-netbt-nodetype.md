# [REQ-END-180] Administrative Templates: Configure NetBT Node Type and Name Release

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-169](../../07-paws/admin-templates/configure-paw-at-netbt-nodetype.md); for Domain Controllers, refer to [REQ-DC-017](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **NetBT Node Type (P-Node)**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\TCPIP Settings\Parameters\NetBT NodeType configuration` -> **Enabled** (Value: `P-node (recommended)`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters`
    * Value Name: `NodeType`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (P-node / Point-to-Point)
  * **NetBIOS Name Release Protection**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers` -> **Enabled**
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters`
    * Value Name: `NoNameReleaseOnDemand`
    * Value Type: `REG_DWORD`
    * Value Data: `1` (Enabled / Ignore unauthenticated release requests)

---

## Rationale
NetBIOS over TCP/IP (NetBT, defined in RFC 1001/1002) is a legacy name resolution and session transport protocol that relies heavily on unauthenticated IP broadcasts over UDP port 137. In modern enterprise environments, NetBT introduces significant attack vectors that can be weaponized for credential theft and denial of service.

### 1. Suppression of Broadcast Name Poisoning (P-Node Enforcement)
The Windows TCP/IP stack supports four NetBIOS node types:
* **1 (B-node / Broadcast)**: Performs name resolution exclusively via IP subnet broadcasts.
* **2 (P-node / Peer-to-Peer)**: Resolves names strictly via directed unicast queries to designated WINS servers. Broadcast queries are entirely prohibited.
* **4 (M-node / Mixed)**: Broadcasts first, then queries WINS if broadcast fails.
* **8 (H-node / Hybrid)**: Queries WINS first, then falls back to subnet broadcast if WINS fails to resolve the name.

In default configurations, Windows systems frequently operate as B-node or H-node. When a client attempts to resolve an unavailable or misspelled network resource, it transmits unauthenticated NetBIOS Name Service (NBNS) broadcast frames across the local collision domain. Threat actors running tools such as Responder or Inveigh capture these broadcasts and reply with forged IP mappings, coercing the victim into initiating NTLM authentication against the adversary's machine. Enforcing **P-node (`NodeType = 2`)** completely eliminates NBNS broadcast generation, neutralizing broadcast poisoning at the transport layer.

### 2. Denial of Service via Spoofed Name Release Requests
NetBT includes an unauthenticated "Name Release" packet type intended to resolve IP address conflicts. If `NoNameReleaseOnDemand` is not explicitly enforced (`0`), any network node can send a spoofed UDP port 137 packet claiming that the victim's NetBIOS computer name conflicts with an existing machine:
* The receiving Windows system immediately relinquishes its registered NetBIOS identity and ceases responding to inbound network requests under that name.
* Attackers can systematically de-register file servers, print servers, or administrative management endpoints, causing targeted network denial of service.
* Setting `NoNameReleaseOnDemand = 1` instructs the Windows network subsystem to ignore all unsolicited Name Release demands unless they originate from an authoritative, trusted WINS server.

### 3. MITRE ATT&CK Mapping
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Intercepting broadcast name requests to capture or relay NTLM credentials.
* **T1040 - Network Sniffing**: Sniffing broadcast name resolution traffic across the local LAN segment.
* **T1498 - Network Denial of Service**: Forcing victim endpoints to surrender their network identities via spoofed name release frames.

---

## Legacy Impact & Compatibility
* **Active Directory DNS Compatibility**: Production Active Directory networks utilize DNS as the primary locator mechanism for Kerberos, LDAP, and SMB communications. Enforcing P-node does not impact DNS name resolution.
* **WINS Server Requirements**: If legacy enterprise line-of-business applications require NetBIOS name resolution, designated WINS servers must be deployed and assigned via DHCP option 44/46. If no WINS servers are configured, NetBT resolution fails silently and queries fall through directly to DNS, which is the desired secure behavior.
* **Peer-to-Peer Workgroups**: Isolated workgroups lacking a local DNS server or WINS infrastructure will experience name resolution failures between local workstations if NetBT is restricted to P-node. Such unmanaged configurations are unsupported in hardened corporate Active Directory architectures.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\TCPIP Settings\Parameters`
  * **NetBT NodeType configuration**: Set to `Enabled`
  * Set **NetBT NodeType** drop-down to: `P-node (recommended)`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers**: Set to `Enabled`

4. Link the GPO to the appropriate Organizational Unit and verify policy enforcement using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtNetbtNodetype.ps1](../implementation_scripts/Configure-EndAtNetbtNodetype.ps1)

```powershell
#Configure-EndAtNetbtNodetype.ps1
# Description: Configures Administrative Templates: Configure NetBT Node Type and Name Release.

Write-Host "Configuring Administrative Templates: Configure NetBT Node Type and Name Release..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure NetBT Node Type and Name Release applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtNetbtNodetypeStatus.ps1](../audit_scripts/Get-EndAtNetbtNodetypeStatus.ps1)

```powershell
#Get-EndAtNetbtNodetypeStatus.ps1
# Description: Audits Administrative Templates: Configure NetBT Node Type and Name Release.

Write-Host "--- Auditing Administrative Templates: Configure NetBT Node Type and Name Release ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$ValueName = "NodeType"
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

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$ValueName = "NoNameReleaseOnDemand"
$ExpectedValue = 1
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.4.7; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.4.7; CIS Windows Server Benchmark: Section 18.4.7
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000215, Windows 11 STIG Rule WN11-CC-000215
* **ANSSI Active Directory Hardening Guide**: Recommendation R42 (Suppression of obsolete name resolution protocols)
* **Microsoft Security Guidance**: NetBIOS over TCP/IP Implementation Specifications (RFC 1001, RFC 1002)
