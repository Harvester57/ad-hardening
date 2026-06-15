# [REQ-NET-002] Restrict RPC Dynamic Ports

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **NTDS RPC Port (DCs only)**: `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
    * Value Name: `TCP/IP Port`
    * Value Type: `REG_DWORD`
    * Recommended Value: `38901` (Decimal)
  * **Netlogon RPC Port (DCs only)**: `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
    * Value Name: `DCTcpipPort`
    * Value Type: `REG_DWORD`
    * Recommended Value: `38902` (Decimal)
  * **DFSR Replication Port (DCs/DFS Members)**: DFSR service WMI configuration or `dfsrdiag.exe`.
    * Recommended Value: `5722` (Decimal)

---

## Rationale
By default, the RPC runtime utilizes a massive dynamic range of high-order ports (TCP 49152-65535) for communication, including Active Directory replication, netlogon authentication, and DFS replication.

Opening this entire dynamic port range in network-based firewalls for all systems exposes an unmonitored attack surface. To mitigate this risk, key domain controller services (NTDS, Netlogon, and DFSR) must be bound to dedicated static ports (TCP 38901, 38902, and 5722 respectively). This allows network administrators to configure precise firewall rules permitting only these ports.

Crucially, **the system-wide dynamic RPC range must NOT be narrowed** (such as restricting it globally to 50000-50100). Restricting the global dynamic range introduces severe risks:
1. **Port Exhaustion**: Under standard server load, limiting the global ephemeral range to a small number of ports can exhaust available sockets, resulting in network failures and domain isolation outages.
2. **Replication Failure**: High volumes of directory transactions can exhaust localized RPC ports.
3. **No Added Security Value**: Narrowing the dynamic range globally does not mitigate standard exploits, and endpoints communicate with local security authority protocols (LSAD/SAMR) over SMB named pipes (`\PIPE\lsass`) rather than directly via dynamic TCP sockets.

Therefore, the system-wide dynamic RPC port range must remain at its default start port (`49152`) and number of ports (`16384`), and any narrowing configurations must be avoided.

---

## Legacy Impact & Compatibility
* **Firewall Coordination**: Network firewall rules permitting TCP ports 38901, 38902, and 5722 must be active and synchronized before configuring these ports, or replication and authentication failures will occur immediately.
* **DFSR Management Tools**: Configuring the DFSR static port dynamically requires the DFS Management Tools feature (`DfsMgmt`) to be installed on the local DC.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Define Static Ports for NTDS and Netlogon via GPO Registry Preferences
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting Domain Controllers (e.g., `GPO_Hardening_DC_RPC`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Define the following **Registry Items**:
   * **NTDS Static Port**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\NTDS\Parameters`
     * **Value Name**: `TCP/IP Port`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `38901` (Decimal)
   * **Netlogon Static Port**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
     * **Value Name**: `DCTcpipPort`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `38902` (Decimal)

#### 2. Ensure System-Wide RPC Port Narrowing is Disabled
Ensure that the registry key `HKLM\SOFTWARE\Microsoft\Rpc\Internet` does **not** exist in your GPOs, as this key enforces restrictive dynamic range overrides. If present, delete the key to allow systems to fall back to the default Windows Server dynamic range (49152-65535).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to configure the RPC static ports and restore default dynamic ranges.

#### Remediation Script:
[Download Script: Set-RPCDynamicPorts.ps1](implementation_scripts/Set-RPCDynamicPorts.ps1)

```powershell
# Set-RPCDynamicPorts.ps1
# Description: Configures static RPC ports for NTDS, Netlogon, and DFSR, and ensures system-wide dynamic RPC ranges are at default values.

Write-Host "Configuring RPC dynamic port restrictions..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    Write-Host "[+] Target is a Domain Controller. Configuring static ports..." -ForegroundColor Gray
    
    # NTDS Static Port -> TCP 38901
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (-not (Test-Path $NtdsPath)) {
        New-Item -Path $NtdsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -Value 38901 -Type DWord
    Write-Host "    NTDS Static Port set to TCP 38901." -ForegroundColor Green
    
    # Netlogon Static Port -> TCP 38902
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $NetlogonPath)) {
        New-Item -Path $NetlogonPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -Value 38902 -Type DWord
    Write-Host "    Netlogon Static Port set to TCP 38902." -ForegroundColor Green

    # DFSR Static Port -> TCP 5722 (if DFSR namespace is present)
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            Set-CimInstance -Query "Select * from DfsrServiceConfiguration" -Namespace "root\MicrosoftDFS" -Property @{ RpcPortAssignment = 5722 } -ErrorAction Stop | Out-Null
            Write-Host "    DFSR Static Replication Port set to TCP 5722." -ForegroundColor Green
        }
    } catch {
        Write-Host "    DFSR WMI configuration not accessible or role not installed. Skipping." -ForegroundColor Yellow
    }
}

# Ensure system-wide dynamic RPC range is at default (start=49152, num=16384)
# In accordance with Microsoft Directory Services guidelines to prevent port exhaustion.
Write-Host "[+] Resetting global dynamic RPC ports to default..." -ForegroundColor Gray

$ProcV4 = Start-Process netsh -ArgumentList "int ipv4 set dynamicport tcp start=49152 num=16384" -Wait -NoNewWindow -PassThru
if ($ProcV4.ExitCode -eq 0) {
    Write-Host "    IPv4 Dynamic Port Range reset to default (49152-65535)." -ForegroundColor Green
} else {
    Write-Error "    Failed to reset IPv4 dynamic port range."
}

$ProcV6 = Start-Process netsh -ArgumentList "int ipv6 set dynamicport tcp start=49152 num=16384" -Wait -NoNewWindow -PassThru
if ($ProcV6.ExitCode -eq 0) {
    Write-Host "    IPv6 Dynamic Port Range reset to default (49152-65535)." -ForegroundColor Green
} else {
    Write-Error "    Failed to reset IPv6 dynamic port range."
}

# Clean HKLM\SOFTWARE\Microsoft\Rpc\Internet range narrowing if present
$RpcInternetPath = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
if (Test-Path $RpcInternetPath) {
    Remove-Item -Path $RpcInternetPath -Force -Recurse | Out-Null
    Write-Host "    Removed restrictive RPC Internet registry settings to restore defaults." -ForegroundColor Green
}

Write-Host "RPC dynamic port configuration applied successfully." -ForegroundColor Cyan
```

#### Audit Script:
[Download Script: Test-RPCDynamicPorts.ps1](audit_scripts/Test-RPCDynamicPorts.ps1)

```powershell
# Test-RPCDynamicPorts.ps1
# Description: Audits dynamic RPC configurations and static ports.

Write-Host "Auditing dynamic RPC configurations..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"
$vulnerable = $false

if ($IsDC) {
    # 1. NTDS Static Port Audit
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $NtdsVal = Get-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -ErrorAction SilentlyContinue
    $NtdsPort = if ($NtdsVal) { $NtdsVal."TCP/IP Port" } else { 0 }
    
    $NtdsColor = if ($NtdsPort -eq 38901) { "Green" } else { "Red"; $vulnerable = $true }
    Write-Host "    - NTDS Static Port: $($NtdsPort) (Expected = 38901)" -ForegroundColor $NtdsColor
    
    # 2. Netlogon Static Port Audit
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $NetlogonVal = Get-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -ErrorAction SilentlyContinue
    $NetlogonPort = if ($NetlogonVal) { $NetlogonVal.DCTcpipPort } else { 0 }
    
    $NetlogonColor = if ($NetlogonPort -eq 38902) { "Green" } else { "Red"; $vulnerable = $true }
    Write-Host "    - Netlogon Static Port: $($NetlogonPort) (Expected = 38902)" -ForegroundColor $NetlogonColor

    # 3. DFSR Port Audit
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            $DfsrPort = $DfsrConfig.RpcPortAssignment
            $DfsrColor = if ($DfsrPort -eq 5722) { "Green" } else { "Red"; $vulnerable = $true }
            Write-Host "    - DFSR Replication Port: $($DfsrPort) (Expected = 5722)" -ForegroundColor $DfsrColor
        }
    } catch {
        Write-Host "    - DFSR role not active or WMI inaccessible." -ForegroundColor Gray
    }
}

# 4. Global Dynamic Port Audit (Netsh query)
Write-Host "[+] Querying active TCP dynamic port settings..." -ForegroundColor Yellow

$IPv4Ports = netsh int ipv4 show dynamicport tcp
$IPv6Ports = netsh int ipv6 show dynamicport tcp

Write-Host "--- IPv4 Dynamic Port Output ---" -ForegroundColor Gray
$IPv4Ports | Out-String | Write-Host -ForegroundColor DarkGray
Write-Host "--- IPv6 Dynamic Port Output ---" -ForegroundColor Gray
$IPv6Ports | Out-String | Write-Host -ForegroundColor DarkGray

# Verify if dynamic ranges are narrowed
$RpcInternetPath = "HKLM:\SOFTWARE\Microsoft\Rpc\Internet"
if (Test-Path $RpcInternetPath) {
    Write-Host "[!] VULNERABLE: Restrictive RPC Internet registry settings found. Narrowing dynamic ranges is not recommended." -ForegroundColor Red
    $vulnerable = $true
} else {
    Write-Host "[+] Restrictive RPC Internet registry settings are absent." -ForegroundColor Green
}

if ($vulnerable) {
    Write-Host "Audit result: NON-COMPLIANT" -ForegroundColor Red
} else {
    Write-Host "Audit result: COMPLIANT" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Administration network subnets)
* **Microsoft Security Guidance**: Restricting Active Directory RPC Traffic to a Specific Port
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
* **DSInternals AD Firewall Guide (Michael Grafnetter)**: [Active Directory Firewall - Domain Controller Firewall](https://firewall.dsinternals.com/ADDS/)
