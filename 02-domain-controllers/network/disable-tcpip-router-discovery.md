# [REQ-DC-148] Disable TCP/IP Router Discovery on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Key**: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * `PerformRouterDiscovery` = `0` (REG_DWORD)

---

## Rationale
The Internet Router Discovery Protocol (IRDP, RFC 1256) enables IPv4 hosts to dynamically discover local default routers by listening for ICMP Router Advertisement packets or soliciting them via ICMP Router Solicitation messages.

On Active Directory Domain Controllers, dynamic router discovery presents a severe attack surface:
1. **Rogue Gateway Redirection**: Attackers positioned on the local network segment can forge unauthenticated ICMP Router Advertisements to advertise a higher-priority default gateway address pointing to an attacker-controlled host.
2. **Man-in-the-Middle (MitM)**: Coercing the Domain Controller to route outbound network traffic through a rogue router allows attackers to intercept, inspect, or modify sensitive replication, Kerberos, LDAP, and DNS communication.

Domain Controllers must operate exclusively with statically assigned or enterprise DHCP-reserved gateway addresses. Setting `PerformRouterDiscovery` to `0` explicitly disables IRDP processing.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Disabling router discovery has no impact on systems that use static default gateway configurations, which is the mandatory baseline standard for Domain Controllers.
* **Compatibility**: Systems will not dynamically reconfigure routing based on ICMP advertisements; all routing relies on statically configured interfaces and local routing tables.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create or update the following Registry Preference (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
   * **Value name**: `PerformRouterDiscovery`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable router discovery on the Domain Controller.

[Download Script: Configure-DisableTcpipRouterDiscovery.ps1](../implementation_scripts/Configure-DisableTcpipRouterDiscovery.ps1)

```powershell
# Configure-DisableTcpipRouterDiscovery.ps1
# Description: Disables IRDP (PerformRouterDiscovery) on Domain Controllers.

Write-Host "Disabling TCP/IP Router Discovery..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}

Set-ItemProperty -Path $TcpipParamsPath -Name "PerformRouterDiscovery" -Value 0 -Type DWord -ErrorAction Stop

Write-Host "TCP/IP Router Discovery disabled successfully (PerformRouterDiscovery = 0)." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-TcpipRouterDiscoveryStatus.ps1](../audit_scripts/Get-TcpipRouterDiscoveryStatus.ps1)

```powershell
# Get-TcpipRouterDiscoveryStatus.ps1
# Description: Audits registry configuration of PerformRouterDiscovery on Domain Controllers.

Write-Host "--- Auditing TCP/IP Router Discovery Status ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ExpectedValue = 0

if (Test-Path -Path $TcpipParamsPath) {
    $Reg = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.PerformRouterDiscovery

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] PerformRouterDiscovery: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] PerformRouterDiscovery: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] TCP/IP Parameters Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.5.2 (Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled')
* **ANSSI AD Hardening Guide**: Security guidelines to prevent dynamic gateway manipulation and network path tampering on Tier 0 assets.
