# [REQ-END-056] Disable Xbox Live Networking Service (XboxNetApiSvc)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-056](../../07-paws/services/disable-xboxnetapisvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Xbox Live Networking Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Xbox Live Networking Service (`XboxNetApiSvc`, hosted in `svchost.exe` via `XboxNetApiSvc.dll`) provides network interface management, peer-to-peer session establishment, and NAT traversal capabilities for Xbox Live multiplayer, party chat, and Windows gaming network APIs.

### 1. Teredo Tunneling and Network Perimeter Evasion
To establish direct peer-to-peer multiplayer and voice connections between clients behind NAT devices, `XboxNetApiSvc` manages and activates Teredo tunneling (RFC 4380):
* **Encapsulation Over UDP 3544**: Teredo encapsulates raw IPv6 packets inside UDP datagrams directed to public Microsoft Teredo relay servers over UDP port 3544.
* **Bypassing Perimeter Security Controls**: Because Teredo encapsulates end-to-end traffic inside UDP datagrams, it can bypass stateful edge firewalls, network-based intrusion detection systems (NIDS/NIPS), and deep packet inspection (DPI) appliances that do not de-encapsulate Teredo frames. This effectively creates an uncontrolled, bidirectional conduit into internal corporate networks.
* **Unsolicited Inbound Network Traffic**: Teredo maintains NAT keep-alives with external relays to allow external hosts to initiate unsolicited inbound connections directly to the internal workstation, defeating standard stateful inbound firewall protections.

### 2. Peer-to-Peer Attack Surface and Network Exposure
* The service exposes network socket handling routines to untrusted internet peers for voice streaming and low-latency game state synchronization.
* Exposing peer-to-peer networking code on corporate workstations introduces exposure to denial-of-service (UDP amplification/flooding), IP address harvesting, and memory corruption vulnerabilities in real-time packet processing libraries.

### 3. Least Functionality in Corporate Workstations
* Enterprise client workstations and member servers have zero operational requirement to support Xbox Live peer-to-peer matchmaking, voice chat, or Teredo NAT traversal.
* Disabling `XboxNetApiSvc` enforces least functionality (NIST SP 800-53 CM-7), closes unmanaged UDP sockets, and prevents covert protocol tunneling across corporate network perimeters.

### 4. MITRE ATT&CK Mapping
* **T1572 - Protocol Tunneling**: Adversaries leveraging or abusing Teredo IPv6-in-UDP tunneling to bypass network perimeter inspection and egress filtering.
* **T1046 - Network Service Discovery**: External or internal discovery of active endpoints through Teredo keep-alive probes.
* **T1210 - Exploitation of Remote Services**: Targeting vulnerabilities in peer-to-peer packet handling routines.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `XboxNetApiSvc` has zero impact on Active Directory domain operations, VPN clients, IPsec tunnels, enterprise web conferencing (Microsoft Teams, Cisco Webex, Zoom), or standard IPv4/IPv6 dual-stack corporate networking.
* **Consumer Gaming Applications**: Multiplayer matchmaking, Xbox party voice chat, and peer-to-peer network multiplayer in Microsoft Store games will be completely disabled. Single-player and standard client-server cloud games remain unaffected.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Networking Service` (`XboxNetApiSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableXboxNetApiSvc.ps1](../implementation_scripts/Configure-DisableXboxNetApiSvc.ps1)

```powershell
# Configure-DisableXboxNetApiSvc.ps1
# Description: Disables the unnecessary Xbox Live Networking Service (XboxNetApiSvc) service.

Write-Host "Applying hardening requirement: Disable Xbox Live Networking Service service..." -ForegroundColor Cyan

$ServiceName = "XboxNetApiSvc"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($ServiceName)"

$Service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $Service) {
    if ($Service.StartType -ne "Disabled") {
        if ($Service.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[+] Service '$($ServiceName)' stopped and disabled." -ForegroundColor Green
    } else {
        Write-Host "[~] Service '$($ServiceName)' is already disabled." -ForegroundColor Gray
    }
} else {
    Write-Host "[~] Service '$($ServiceName)' is not installed." -ForegroundColor Gray
}

if (Test-Path -Path $RegPath) {
    Set-ItemProperty -Path $RegPath -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[+] Registry Start value set to 4 (Disabled) for service '$($ServiceName)'." -ForegroundColor Green
}
```

*To verify the startup type of this unnecessary service:*

[Download Script: Get-XboxNetApiSvcStatus.ps1](../audit_scripts/Get-XboxNetApiSvcStatus.ps1)

```powershell
# Get-XboxNetApiSvcStatus.ps1
# Description: Audits the startup configuration of Xbox Live Networking Service (XboxNetApiSvc) service.

Write-Host "--- Auditing Xbox Live Networking Service (XboxNetApiSvc) Service ---" -ForegroundColor Cyan

$ServiceName = "XboxNetApiSvc"
$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($ServiceName)"
$IsVulnerable = $false

if (Test-Path -Path $RegPath) {
    $StartVal = Get-ItemProperty -Path $RegPath -Name "Start" -ErrorAction SilentlyContinue
    if ($null -ne $StartVal) {
        $Start = $StartVal.Start
        if ($Start -eq 4) {
            Write-Host "[+] Service '$($ServiceName)' is secure (Disabled)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: Service '$($ServiceName)' startup type is not Disabled (Start value is $($Start))." -ForegroundColor Red
            $IsVulnerable = $true
        }
    } else {
        Write-Host "[!] VULNERABLE: Service '$($ServiceName)' exists but Start registry value is missing." -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "[+] Service '$($ServiceName)' is not installed (Secure)." -ForegroundColor Green
}

if ($IsVulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Client Benchmark**: Section 5.47 (XboxNetApiSvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
