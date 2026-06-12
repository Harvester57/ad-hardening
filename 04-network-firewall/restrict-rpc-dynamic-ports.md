# Hardening Requirement: Restrict RPC Dynamic Ports

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
  * **Netlogon RPC Port (DCs only)**: `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
    * Value Name: `DCTcpipPort`
    * Value Type: `REG_DWORD`
  * **DFSR Replication Port (DCs/DFS Members)**: DFSR service WMI configuration or `dfsrdiag.exe`.
  * **System RPC Dynamic Port Range (Global)**:
    * Command: `netsh int ipv4 set dynamicport tcp` / `netsh int ipv6 set dynamicport tcp`
    * Registry: `HKLM\SOFTWARE\Microsoft\Rpc\Internet`

---

## Rationale
By default, the RPC runtime utilizes a massive dynamic range of high-order ports (TCP 49152-65535) for communication, including Active Directory replication, netlogon authentication, and DFS replication.

Opening this full port range in perimeter and internal network firewalls exposes a vast, unmonitored attack surface. Threat actors on compromised member endpoints can scan these high-order ports to discover Active Directory services, perform targeted exploits, or intercept unencrypted network transactions.

Restricting dynamic RPC to a narrow, predictable range (e.g., TCP 50000-50100) or binding services to specific static ports (e.g., NTDS to TCP 50000, Netlogon to TCP 50001, and DFSR to TCP 50002) allows security engineers to configure extremely tight firewall rules, effectively blocking access to unauthorized high-order TCP ports.

---

## Legacy Impact & Compatibility
* **Firewall Coordination**: Firewall rules permitting the restricted dynamic range must be active before applying this setting, or replication and authentication failures will occur immediately.
* **Port Availability**: The chosen static/dynamic ports must not be utilized by any other software running on the servers.
* **Non-AD RPC Traffic**: Any third-party software on member servers that relies on the default ephemeral port range may need configuration if the system-wide dynamic RPC port range is restricted.

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
     * **Value Data**: `50000` (Decimal)
   * **Netlogon Static Port**:
     * **Action**: `Update`
     * **Hive**: `HKEY_LOCAL_MACHINE`
     * **Key Path**: `SYSTEM\CurrentControlSet\Services\Netlogon\Parameters`
     * **Value Name**: `DCTcpipPort`
     * **Value Type**: `REG_DWORD`
     * **Value Data**: `50001` (Decimal)

#### 2. Restrict Dynamic RPC Port Range (System-Wide)
To enforce the dynamic port range restriction across Member Servers and Domain Controllers:
Create or edit a GPO (e.g., `GPO_Hardening_RPC_Range`) and apply Registry Preferences under:
`Computer Configuration\Preferences\Windows Settings\Registry`

* **Dynamic Ports Range Configuration**:
  * **Registry Key**: `HKLM\SOFTWARE\Microsoft\Rpc\Internet`
  * Add the following values:
    * Value Name: `Ports` | Type: `REG_MULTI_SZ` | Value Data: `50000-50100`
    * Value Name: `PortsInternetAvailable` | Type: `REG_SZ` | Value Data: `Y`
    * Value Name: `UsePorts` | Type: `REG_SZ` | Value Data: `Y`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to audit and restrict the RPC dynamic port configuration.

#### Remediation Script:
[Download Script: Set-RPCDynamicPorts.ps1](implementation_scripts/Set-RPCDynamicPorts.ps1)

```powershell
# Set-RPCDynamicPorts.ps1
# Configures static RPC ports for NTDS/Netlogon and restricts system-wide ephemeral range.

Write-Host "Configuring RPC dynamic port restrictions..." -ForegroundColor Cyan

# 1. If Domain Controller, configure static ports for NTDS and Netlogon
$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    Write-Host "[+] Target is a Domain Controller. Configuring NTDS and Netlogon static ports..." -ForegroundColor Gray
    
    # NTDS Static Port -> TCP 50000
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (-not (Test-Path $NtdsPath)) {
        New-Item -Path $NtdsPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -Value 50000 -Type DWord
    Write-Host "    NTDS Static Port set to TCP 50000." -ForegroundColor Green
    
    # Netlogon Static Port -> TCP 50001
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    if (-not (Test-Path $NetlogonPath)) {
        New-Item -Path $NetlogonPath -Force | Out-Null
    }
    Set-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -Value 50001 -Type DWord
    Write-Host "    Netlogon Static Port set to TCP 50001." -ForegroundColor Green

    # DFSR Static Port -> TCP 50002 (if DFSR namespace is present)
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            Set-CimInstance -Query "Select * from DfsrServiceConfiguration" -Namespace "root\MicrosoftDFS" -Property @{ RpcPortAssignment = 50002 } -ErrorAction Stop | Out-Null
            Write-Host "    DFSR Static Replication Port set to TCP 50002." -ForegroundColor Green
        }
    } catch {
        Write-Host "    DFSR WMI configuration not accessible or role not installed. Skipping." -ForegroundColor Yellow
    }
}

# 2. Restrict system-wide dynamic RPC port range (50000 - 50100)
Write-Host "[+] Enforcing global dynamic RPC ports via Netsh..." -ForegroundColor Gray

# Configure IPv4 Dynamic Ports
$ProcV4 = Start-Process netsh -ArgumentList "int ipv4 set dynamicport tcp start=50000 num=100" -Wait -NoNewWindow -PassThru
if ($ProcV4.ExitCode -eq 0) {
    Write-Host "    IPv4 Dynamic Port Range set to 50000-50100." -ForegroundColor Green
} else {
    Write-Error "    Failed to set IPv4 dynamic port range."
}

# Configure IPv6 Dynamic Ports
$ProcV6 = Start-Process netsh -ArgumentList "int ipv6 set dynamicport tcp start=50000 num=100" -Wait -NoNewWindow -PassThru
if ($ProcV6.ExitCode -eq 0) {
    Write-Host "    IPv6 Dynamic Port Range set to 50000-50100." -ForegroundColor Green
} else {
    Write-Error "    Failed to set IPv6 dynamic port range."
}

Write-Host "RPC Dynamic Port configuration applied successfully." -ForegroundColor Cyan
```

#### Audit Script:
[Download Script: Test-RPCDynamicPorts.ps1](audit_scripts/Test-RPCDynamicPorts.ps1)

```powershell
# Test-RPCDynamicPorts.ps1
# Audits dynamic RPC configurations and static ports.

Write-Host "Auditing dynamic RPC configurations..." -ForegroundColor Cyan

$IsDC = (Get-CimInstance -ClassName Win32_ComputerSystem).Roles -contains "Primary_Domain_Controller"

if ($IsDC) {
    # 1. NTDS Static Port Audit
    $NtdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $NtdsVal = Get-ItemProperty -Path $NtdsPath -Name "TCP/IP Port" -ErrorAction SilentlyContinue
    $NtdsPort = if ($NtdsVal) { $NtdsVal."TCP/IP Port" } else { 0 }
    
    $NtdsColor = if ($NtdsPort -eq 50000) { "Green" } else { "Red" }
    Write-Host "    - NTDS Static Port: $($NtdsPort) (Expected = 50000)" -ForegroundColor $NtdsColor
    
    # 2. Netlogon Static Port Audit
    $NetlogonPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $NetlogonVal = Get-ItemProperty -Path $NetlogonPath -Name "DCTcpipPort" -ErrorAction SilentlyContinue
    $NetlogonPort = if ($NetlogonVal) { $NetlogonVal.DCTcpipPort } else { 0 }
    
    $NetlogonColor = if ($NetlogonPort -eq 50001) { "Green" } else { "Red" }
    Write-Host "    - Netlogon Static Port: $($NetlogonPort) (Expected = 50001)" -ForegroundColor $NetlogonColor

    # 3. DFSR Port Audit
    try {
        $DfsrConfig = Get-CimInstance -Namespace "root\MicrosoftDFS" -ClassName DfsrServiceConfiguration -ErrorAction Stop
        if ($null -ne $DfsrConfig) {
            $DfsrPort = $DfsrConfig.RpcPortAssignment
            $DfsrColor = if ($DfsrPort -eq 50002) { "Green" } else { "Red" }
            Write-Host "    - DFSR Replication Port: $($DfsrPort) (Expected = 50002)" -ForegroundColor $DfsrColor
        }
    } catch {
        Write-Host "    - DFSR role not available on this server." -ForegroundColor Gray
    }
}

# 4. Global Dynamic Port Audit (Netsh query)
Write-Host "[+] Querying active TCP dynamic port settings..." -ForegroundColor Yellow

$IPv4Ports = netsh int ipv4 show dynamicport tcp
$IPv6Ports = netsh int ipv6 show dynamicport tcp

# Parse netsh output (look for "Start Port" or number of ports)
$IPv4Match = $IPv4Ports -join "`n"
$IPv6Match = $IPv6Ports -join "`n"

Write-Host "--- IPv4 Dynamic Port Output ---" -ForegroundColor Gray
Write-Host $IPv4Match -ForegroundColor DarkGray
Write-Host "--- IPv6 Dynamic Port Output ---" -ForegroundColor Gray
Write-Host $IPv6Match -ForegroundColor DarkGray
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R8 (Administration network subnets)
* **Microsoft Security Guidance**: Restricting Active Directory RPC Traffic to a Specific Port
* **CIS Windows Server 2016 Benchmark**: Section 19 (Windows Defender Firewall with Advanced Security)
