# [REQ-DC-149] Configure TCP Max Data Retransmissions on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Keys**:
    * `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
      * `TcpMaxDataRetransmissions` = `3` (REG_DWORD)
    * `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
      * `TcpMaxDataRetransmissions` = `3` (REG_DWORD)

---

## Rationale
The `TcpMaxDataRetransmissions` parameter determines the number of times TCP will retransmit an individual data segment (non-connect segment) before aborting the connection. The retransmission timeout is doubled with each successive retransmission on a connection, backed off exponentially.

By default, Windows configures `TcpMaxDataRetransmissions` to `5`, which causes the system to wait over 200 seconds before terminating an unresponsive connection. In an Active Directory environment:
1. **Resource Exhaustion Mitigation**: Restricting retransmissions to `3` causes stalled or unresponsive connections to be severed significantly faster, releasing kernel memory buffers, TCP control blocks (TCBs), and socket handles.
2. **Denial-of-Service Defense**: In scenarios involving connection drop attacks, network partitions, or resource starvation attempts, limiting TCP data retransmissions for both IPv4 and IPv6 prevents connection pool depletion on Domain Controllers.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Configuring TCP data retransmissions to `3` provides ample resilience on enterprise networks with minimal packet loss while cleaning up dead connections much faster.
* **High-Latency Links**: If Domain Controllers replicate across exceptionally degraded WAN or satellite links with severe packet loss, connections may terminate sooner. Ensure underlying WAN links meet enterprise reliability standards.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the GPO linked to the Domain Controllers OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to: `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create or update the following Registry Preferences (Right-click **Registry -> New -> Registry Item**):
   * **IPv4 TCP Max Data Retransmissions**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
     * **Value name**: `TcpMaxDataRetransmissions`
     * **Value type**: `REG_DWORD`
     * **Value data**: `3` (Decimal)
   * **IPv6 TCP Max Data Retransmissions**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
     * **Value name**: `TcpMaxDataRetransmissions`
     * **Value type**: `REG_DWORD`
     * **Value data**: `3` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure `TcpMaxDataRetransmissions` for IPv4 and IPv6 on the Domain Controller.

[Download Script: Configure-TcpipMaxDataRetransmissions.ps1](../implementation_scripts/Configure-TcpipMaxDataRetransmissions.ps1)

```powershell
# Configure-TcpipMaxDataRetransmissions.ps1
# Description: Sets TcpMaxDataRetransmissions to 3 for IPv4 and IPv6 on Domain Controllers.

Write-Host "Configuring TCP Max Data Retransmissions (IPv4 and IPv6)..." -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
if (-not (Test-Path -Path $TcpipParamsPath)) {
    New-Item -Path $TcpipParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $TcpipParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
if (-not (Test-Path -Path $Tcpip6ParamsPath)) {
    New-Item -Path $Tcpip6ParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $Tcpip6ParamsPath -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord -ErrorAction Stop

Write-Host "TCP Max Data Retransmissions configured to 3 for IPv4 and IPv6." -ForegroundColor Green
```

*To verify the setting has been applied:*

[Download Script: Get-TcpipMaxDataRetransmissionsStatus.ps1](../audit_scripts/Get-TcpipMaxDataRetransmissionsStatus.ps1)

```powershell
# Get-TcpipMaxDataRetransmissionsStatus.ps1
# Description: Audits registry configuration of TcpMaxDataRetransmissions for IPv4 and IPv6 on Domain Controllers.

Write-Host "--- Auditing TCP Max Data Retransmissions Status ---" -ForegroundColor Cyan

$TcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$Tcpip6ParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$IsVulnerable = $false

if (Test-Path -Path $TcpipParamsPath) {
    $Reg4 = Get-ItemProperty -Path $TcpipParamsPath -ErrorAction SilentlyContinue
    $Val4 = $Reg4.TcpMaxDataRetransmissions
    if ($Val4 -eq 3) {
        Write-Host "    [+] IPv4 TcpMaxDataRetransmissions: $($Val4) (Expected: 3)" -ForegroundColor Green
    } else {
        Write-Host "    [!] IPv4 TcpMaxDataRetransmissions: $($Val4) (Expected: 3)" -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "    [!] IPv4 Parameters Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if (Test-Path -Path $Tcpip6ParamsPath) {
    $Reg6 = Get-ItemProperty -Path $Tcpip6ParamsPath -ErrorAction SilentlyContinue
    $Val6 = $Reg6.TcpMaxDataRetransmissions
    if ($Val6 -eq 3) {
        Write-Host "    [+] IPv6 TcpMaxDataRetransmissions: $($Val6) (Expected: 3)" -ForegroundColor Green
    } else {
        Write-Host "    [!] IPv6 TcpMaxDataRetransmissions: $($Val6) (Expected: 3)" -ForegroundColor Red
        $IsVulnerable = $true
    }
} else {
    Write-Host "    [!] IPv6 Parameters Registry Path NOT FOUND" -ForegroundColor Red
    $IsVulnerable = $true
}

if ($IsVulnerable) {
    exit 1
} else {
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.5.3 (Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to '3') and Section 18.5.4 (Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to '3')
* **ANSSI AD Hardening Guide**: Security guidelines to optimize TCP/IP stack parameters and mitigate connection state exhaustion on Domain Controllers.
