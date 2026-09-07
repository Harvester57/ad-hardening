# [REQ-DC-147] Configure TCP/IP KeepAliveTime on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Key**: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
    * `KeepAliveTime` = `300000` (REG_DWORD)

---

## Rationale
The `KeepAliveTime` parameter controls how often TCP attempts to verify that an idle connection is still intact by sending a keep-alive packet. If the remote system is still reachable and functioning, it acknowledges the keep-alive transmission. 

In Active Directory environments, Domain Controllers manage high volumes of concurrent Kerberos, LDAP, SMB, and RPC sessions with member servers and workstations. Configuring `KeepAliveTime` to 300,000 milliseconds (5 minutes) instead of the default 2 hours (7,200,000 ms) ensures orphaned or dead TCP connections from abruptly disconnected clients are detected and reclaimed promptly. This mitigates half-open connection accumulation and denial-of-service risks against server connection pools.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Tuning keep-alive time to 5 minutes does not affect active directory replication, client authentication, DNS resolution, or administrative connections.
* **Network Traversal**: Firewalls and intermediate stateful NAT gateways that drop idle sessions after a short inactivity period benefit from shorter keep-alive intervals, as keep-alive packets prevent unexpected connection teardowns.

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
   * **Value name**: `KeepAliveTime`
   * **Value type**: `REG_DWORD`
   * **Value data**: `300000` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure `KeepAliveTime` on the Domain Controller.

[Download Script: Configure-TcpipKeepAliveTime.ps1](../implementation_scripts/Configure-TcpipKeepAliveTime.ps1)

```powershell
# Configure-TcpipKeepAliveTime.ps1
# Description: Configures TCP/IP KeepAliveTime parameter to 300000 ms (5 minutes) on Domain Controllers.

Write-Host "Configuring TCP/IP KeepAliveTime..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}

Set-ItemProperty -Path $TcpipParamsPath -Name "KeepAliveTime" -Value 300000 -Type DWord -ErrorAction Stop

Write-Host "TCP/IP KeepAliveTime configured successfully (300000 ms)." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-TcpipKeepAliveTimeStatus.ps1](../audit_scripts/Get-TcpipKeepAliveTimeStatus.ps1)

```powershell
# Get-TcpipKeepAliveTimeStatus.ps1
# Description: Audits registry configuration of TCP/IP KeepAliveTime on Domain Controllers.

Write-Host "--- Auditing TCP/IP KeepAliveTime ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$ExpectedValue = 300000

if (Test-Path -Path $TcpipParamsPath) {
    $Reg = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $CurrentValue = $Reg.KeepAliveTime

    if ($CurrentValue -eq $ExpectedValue) {
        Write-Host "    [+] KeepAliveTime: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "    [!] KeepAliveTime: $($CurrentValue) (Expected: $($ExpectedValue))" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "    [!] TCP/IP Parameters Registry Path NOT FOUND" -ForegroundColor Red
    exit 1
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.5.1 (Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to '300,000 or 5 minutes (recommended)')
* **ANSSI AD Hardening Guide**: Security guidelines to optimize protocol parameters and connection lifecycle management on Domain Controllers.
