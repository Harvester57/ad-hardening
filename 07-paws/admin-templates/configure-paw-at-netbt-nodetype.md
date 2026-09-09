# [REQ-PAW-169] Administrative Templates: Configure NetBT Node Type and Name Release for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-180](../../08-endpoints/admin-templates/configure-end-at-netbt-nodetype.md); for Domain Controllers, refer to [REQ-DC-017](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) are high-value targets operating within dedicated administrative management zones. Permitting unauthenticated broadcast resolution protocols on a PAW introduces critical risks of credential relay and network-level denial of service.

### 1. Eliminating Broadcast Poisoning Vectors on Tier 0 Management Hosts
If a PAW attempts to resolve a hostname that is misspelled or temporarily unreachable via DNS, standard Windows configurations fall back to NetBIOS over TCP/IP (NetBT) broadcast queries over UDP port 137. 
* Attackers positioned on the management segment or utilizing compromised intermediary switches can use tools like Responder or Inveigh to spoof NBNS responses.
* The PAW's local security authority would then attempt an NTLM authentication handshake against the attacker's IP, exposing highly sensitive Tier 0 administrative Kerberos tickets or NTLMv2 challenge-response hashes.
* Configuring **P-node (`NodeType = 2`)** completely disables broadcast name resolution. The PAW will only query authoritative unicast servers, eliminating the generation of unauthenticated broadcast traffic.

### 2. Guarding Against Host Identity Hijacking and DoS
In default configurations, Windows endpoints honor unauthenticated NetBIOS Name Release packets sent across the local subnet.
* A rogue actor or compromised host on the network can transmit forged Name Release packets targeting the PAW's registered NetBIOS identity.
* The PAW would immediately surrender its NetBIOS name registration, causing Active Directory management tools, Remote Server Administration Tools (RSAT), and remote PowerShell sessions to disconnect.
* Setting `NoNameReleaseOnDemand = 1` ensures that the PAW ignores all unauthenticated name release demands, accepting identity management directives exclusively from authenticated, authoritative WINS servers.

### 3. MITRE ATT&CK Mapping
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Poisoning broadcast name resolution to intercept administrative credentials.
* **T1040 - Network Sniffing**: Capturing broadcast resolution traffic on privileged administrative segments.
* **T1498 - Network Denial of Service**: Disrupting administrative session availability via spoofed name release frames.

---

## Legacy Impact & Compatibility
* **Enterprise Administrative Compatibility**: Tier 0 administrative activities rely exclusively on Active Directory integrated DNS infrastructure. Domain Controllers, administrative hypervisors, and directory services communicate via fully qualified domain names (FQDNs) and Kerberos SPNs. P-node enforcement has zero impact on legitimate directory administration.
* **WINS Requirements**: If legacy management networks utilize WINS, the PAW can query the designated WINS server via unicast. If WINS is absent, the PAW relies purely on secure DNS resolution.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\TCPIP Settings\Parameters`
  * **NetBT NodeType configuration**: Set to `Enabled`
  * Set **NetBT NodeType** drop-down to: `P-node (recommended)`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers**: Set to `Enabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtNetbtNodetype.ps1](../implementation_scripts/Configure-PawAtNetbtNodetype.ps1)

```powershell
#Configure-PawAtNetbtNodetype.ps1
# Description: Configures Administrative Templates: Configure NetBT Node Type and Name Release for PAWs.

Write-Host "Configuring Administrative Templates: Configure NetBT Node Type and Name Release for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NodeType" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Configure NetBT Node Type and Name Release for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtNetbtNodetypeStatus.ps1](../audit_scripts/Get-PawAtNetbtNodetypeStatus.ps1)

```powershell
#Get-PawAtNetbtNodetypeStatus.ps1
# Description: Audits Administrative Templates: Configure NetBT Node Type and Name Release for PAWs.

Write-Host "--- Auditing Administrative Templates: Configure NetBT Node Type and Name Release for PAWs ---" -ForegroundColor Cyan
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.4.7; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.4.7
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000215, Windows 11 STIG Rule WN11-CC-000215
* **ANSSI Active Directory Hardening Guide**: Recommendation R42 (Suppression of obsolete name resolution protocols)
* **Microsoft Privileged Access Workstation Guidance**: Network Profile Isolation and Protocol Hardening Specifications
