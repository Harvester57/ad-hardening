# [REQ-PAW-170] Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-181](../../08-endpoints/admin-templates/configure-end-at-mss-ip-source-routing.md); for Domain Controllers, refer to [REQ-DC-018](../../02-domain-controllers/harden-network-parameters.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Paths / Registry Locations**:
  * **IPv6 IP Source Routing Protection**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (DisableIPSourceRouting IPv6) IP source routing protection level` -> **Enabled** (Value: `Highest protection, source routing is completely disabled`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
    * Value Name: `DisableIPSourceRouting`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Highest protection)
  * **IPv4 IP Source Routing Protection**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (DisableIPSourceRouting) IP source routing protection level` -> **Enabled** (Value: `Highest protection, source routing is completely disabled`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * Value Name: `DisableIPSourceRouting`
    * Value Type: `REG_DWORD`
    * Value Data: `2` (Highest protection)
  * **Disable ICMP Redirect Processing**:
    * GPO Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes` -> **Disabled**
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * Value Name: `EnableICMPRedirect`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled / Ignore ICMP redirects)

---

## Rationale
Privileged Access Workstations (PAWs) establish highly privileged administrative sessions (including Kerberos-authenticated WinRM, Remote Desktop with Restricted Admin mode, and LDAP over TLS) to Tier 0 infrastructure. Preserving absolute network routing integrity is critical to prevent traffic interception or session manipulation.

### 1. Protection Against Administrative Session Redirection
Unauthenticated ICMP Type 5 Redirect messages can be used by an attacker on an adjacent subnet to manipulate the PAW's local IP routing table:
* An attacker can forge ICMP redirect messages indicating that traffic directed toward Domain Controllers or management hypervisors should traverse an intermediary attacking host.
* If the PAW's TCP/IP stack accepts the redirect, outbound administrative management traffic is redirected through the adversary's machine, exposing the operator to TLS downgrade attacks, NTLM relaying, or credential harvesting.
* Enforcing `EnableICMPRedirect = 0` guarantees that the PAW strictly adheres to statically configured or DHCP-provisioned default gateways, ignoring all dynamically injected ICMP route modifications.

### 2. Elimination of IP Source Routing Vectors
IP Source Routing allows packet senders to specify intermediate transit hops:
* Attackers can abuse loose or strict source routing to bypass boundary firewalls isolating the PAW management network from general enterprise subnets.
* By specifying reverse source routing paths, an attacker can conduct blind TCP spoofing attacks against listening management services.
* Enforcing `DisableIPSourceRouting = 2` on both IPv4 and IPv6 stacks instructs the Windows kernel to unconditionally drop all packets containing source route options, ensuring that the PAW only communicates over deterministically routed enterprise paths.

### 3. MITRE ATT&CK Mapping
* **T1557 - Adversary-in-the-Middle**: Route manipulation to intercept administrative sessions between PAWs and Domain Controllers.
* **T1565.002 - Data Manipulation: Transmitted Data Manipulation**: Unauthorized modification of routing paths for privileged traffic.
* **T1498 - Network Denial of Service**: Disruption of administrative access via malicious gateway manipulation.

---

## Legacy Impact & Compatibility
* **Operational Impact**: None. Tier 0 administrative networks utilize dedicated, deterministic routing infrastructure. PAWs have no requirement to process ICMP redirects or handle source-routed packets.
* **Management Traffic Integrity**: Hardening the TCP/IP stack guarantees that administrative sessions to Domain Controllers remain strictly confined to designated management transit links.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (DisableIPSourceRouting IPv6) IP source routing protection level**: Set to `Enabled`
  * Select drop-down value: `Highest protection, source routing is completely disabled`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (DisableIPSourceRouting) IP source routing protection level**: Set to `Enabled`
  * Select drop-down value: `Highest protection, source routing is completely disabled`
* Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtMssIpSourceRouting.ps1](../implementation_scripts/Configure-PawAtMssIpSourceRouting.ps1)

```powershell
#Configure-PawAtMssIpSourceRouting.ps1
# Description: Configures Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs.

Write-Host "Configuring Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableICMPRedirect" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtMssIpSourceRoutingStatus.ps1](../audit_scripts/Get-PawAtMssIpSourceRoutingStatus.ps1)

```powershell
#Get-PawAtMssIpSourceRoutingStatus.ps1
# Description: Audits Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs.

Write-Host "--- Auditing Administrative Templates: MSS IP Source Routing and ICMP Redirects for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$ValueName = "DisableIPSourceRouting"
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

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ValueName = "DisableIPSourceRouting"
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

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ValueName = "EnableICMPRedirect"
$ExpectedValue = 0
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
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.5.8, Section 18.5.9, Section 18.5.10; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.5.8, Section 18.5.9, Section 18.5.10
* **DISA STIG**: Windows 10 STIG Rules WN10-SO-000185, WN10-SO-000190, WN10-SO-000195
* **ANSSI Active Directory Hardening Guide**: Section 3.2.4 (TCP/IP Stack Hardening on Managed Nodes)
* **Microsoft Privileged Access Workstation Guidance**: Tier 0 Network Boundary Protection Specifications
