# [REQ-DC-150] Disable Default IPv6 DNS Servers on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
    * **Policy**: `Turn off default IPv6 DNS Servers` -> **Enabled**
  * **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
    * `DisableIPv6DefaultDnsServers` = `1` (REG_DWORD)

---

## Rationale
By default, the Windows DNS client may fall back to well-known default IPv6 DNS addresses (such as site-local or router-advertised dynamic addresses) if statically configured DNS servers fail to respond, or when processing IPv6 router advertisements (RAs) via DHCPv6 / SLAAC.

In an Active Directory environment:
1. **MitM and Rogue IPv6 DNS Redirection**: Attackers on the local network segment utilize tools like `mitm6` to broadcast rogue IPv6 Router Advertisements and rogue DHCPv6 replies, assigning an attacker-controlled IPv6 DNS server to systems on the subnet.
2. **Credential Relay & Authentication Coercion**: When a Domain Controller queries DNS through a rogue IPv6 DNS server, the attacker can spoof hostnames (such as internal WPAD, CRL endpoints, or management servers) to coerce LDAP/SMB/HTTP authentication and perform NTLM relay attacks.

Enabling `Turn off default IPv6 DNS Servers` (`DisableIPv6DefaultDnsServers = 1`) ensures that the DNS Client service does not fall back to default or dynamically acquired IPv6 DNS server addresses, confining DNS resolution strictly to administratively approved directory DNS servers.

---

## Legacy Impact & Compatibility
* **Normal Operations**: If the enterprise network uses dual-stack IPv4/IPv6, enterprise IPv6 DNS servers should be explicitly configured on the network adapter properties or via enterprise DHCPv6 options. Disabling default/fallback IPv6 DNS servers prevents unauthenticated fallback without interrupting explicit configurations.
* **AD Replication & Authentication**: Core AD functionality relies on explicit DNS resolution. As long as domain DNS servers are properly defined in network adapter settings, disabling default IPv6 DNS servers has zero negative operational impact.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\DNS Client`
4. Configure the policy:
   * **Setting**: `Turn off default IPv6 DNS Servers`
   * **State**: **Enabled**

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to disable default IPv6 DNS servers on the Domain Controller.

[Download Script: Configure-DisableIPv6DefaultDnsServers.ps1](../implementation_scripts/Configure-DisableIPv6DefaultDnsServers.ps1)

```powershell
# Configure-DisableIPv6DefaultDnsServers.ps1
# Description: Disables default IPv6 DNS servers in DNS Client policy on Domain Controllers.

Write-Host "Disabling default IPv6 DNS servers..." -ForegroundColor Cyan

$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path -Path $DnsClientPath)) {
    New-Item -Path $DnsClientPath -Force | Out-Null
}

Set-ItemProperty -Path $DnsClientPath -Name "DisableIPv6DefaultDnsServers" -Value 1 -Type DWord -ErrorAction Stop

Write-Host "Default IPv6 DNS servers disabled successfully (DisableIPv6DefaultDnsServers = 1)." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-DisableIPv6DefaultDnsServersStatus.ps1](../audit_scripts/Get-DisableIPv6DefaultDnsServersStatus.ps1)

```powershell
# Get-DisableIPv6DefaultDnsServersStatus.ps1
# Description: Audits registry configuration of DisableIPv6DefaultDnsServers on Domain Controllers.

Write-Host "--- Auditing DisableIPv6DefaultDnsServers Status ---" -ForegroundColor Cyan

$DnsClientPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$ExpectedValue = 1

if (Test-Path -Path $DnsClientPath) {
    $Reg = Get-ItemProperty -Path $DnsClientPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.DisableIPv6DefaultDnsServers

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] DisableIPv6DefaultDnsServers: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] DisableIPv6DefaultDnsServers: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] DNS Client Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.6.4.1 (Ensure 'Turn off default IPv6 DNS Servers' is set to 'Enabled')
* **ANSSI AD Hardening Guide**: Protective measures against local name resolution poisoning and rogue IPv6 router advertisement attacks.
