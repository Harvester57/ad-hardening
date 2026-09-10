# [REQ-END-045] Disable Simple TCP/IP Services (simptcp)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-045](../../07-paws/services/disable-simptcp.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Simple TCP/IP Services` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\simptcp`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Simple TCP/IP Services (`simptcp`) implement a suite of legacy diagnostic protocols conceived in the 1980s over both TCP and UDP: Echo (port 7, RFC 862), Discard (port 9, RFC 863), Character Generator / Chargen (port 19, RFC 864), Daytime (port 13, RFC 867), and Quote of the Day / QOTD (port 17, RFC 865).

### 1. Inherent Insecurity and Amplification Denial of Service Attacks
Enabling Simple TCP/IP Services introduces dangerous denial-of-service vulnerabilities:
* **UDP Reflection and Amplification DDoS**: The Chargen (UDP port 19) and Echo (UDP port 7) services are widely weaponized in reflection and amplification attacks. An attacker can transmit spoofed UDP datagrams containing the victim's source IP address to endpoints running `simptcp`. In response, Chargen transmits a continuous flood of random ASCII characters to the victim, yielding massive bandwidth amplification factors (exceeding 300x) that exhaust network capacity (MITRE ATT&CK T1498.002 - Network Denial of Service: Reflection Amplification).
* **Endless Loop Flooding**: By spoofing a packet originating from a target host's Echo port directed at another host's Echo or Chargen port, an adversary can induce an infinite packet bounce loop between the two machines, consuming 100% of host CPU and network buffer resources (T1499 - Endpoint Denial of Service).
* **Network Reconnaissance**: Unauthenticated services like Daytime and Quote of the Day leak host responsiveness, exact local system clock readings, and operating system signatures to network scanners without generating audit logs (T1046 - Network Service Discovery).

### 2. Least Functionality in Modern Enterprise Networks
In enterprise Active Directory environments:
* Modern network diagnostics rely on ICMP echo requests, PowerShell `Test-NetConnection`, and SNMP/WMI monitoring. Obsolete RFC 86x protocols have been completely superseded.
* Disabling `simptcp` closes 10 distinct listening network sockets (ports 7, 9, 13, 17, and 19 over both TCP and UDP), eliminating reflection attack vectors across the workstation fleet.

### 3. MITRE ATT&CK Mapping
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Weaponizing UDP Chargen and Echo ports in reflection attacks.
* **T1499 - Endpoint Denial of Service**: Triggering endless loop denial of service conditions between network endpoints.
* **T1046 - Network Service Discovery**: Adversaries probing legacy diagnostic ports to identify and profile active endpoints.

---

## Legacy Impact & Compatibility
* **Standard Network Connectivity**: Standard TCP/IP networking, DNS resolution, DHCP addressing, and ICMP ping operate without interruption.
* **Modern Diagnostics**: Administrative and diagnostic utilities (e.g., `ping.exe`, `Test-NetConnection`, `pathping.exe`) do not utilize Simple TCP/IP Services.
* **Operational Transparency**: Disabling `simptcp` is 100% transparent across all production enterprise environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Simple TCP/IP Services` (`simptcp`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disablesimptcp.ps1](../implementation_scripts/Configure-Disablesimptcp.ps1)

```powershell
# Configure-Disablesimptcp.ps1
# Description: Disables the unnecessary Simple TCP/IP Services (simptcp) service.

Write-Host "Applying hardening requirement: Disable Simple TCP/IP Services service..." -ForegroundColor Cyan

$ServiceName = "simptcp"
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

[Download Script: Get-simptcpStatus.ps1](../audit_scripts/Get-simptcpStatus.ps1)

```powershell
# Get-simptcpStatus.ps1
# Description: Audits the startup configuration of Simple TCP/IP Services (simptcp) service.

Write-Host "--- Auditing Simple TCP/IP Services (simptcp) Service ---" -ForegroundColor Cyan

$ServiceName = "simptcp"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.29 (simptcp)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
