# [REQ-PAW-045] Disable Simple TCP/IP Services for PAWs (simptcp)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-045](../../08-endpoints/services/disable-simptcp.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The Simple TCP/IP Services (`simptcp`) implement a suite of legacy diagnostic protocols (Echo, Discard, Character Generator, Daytime, and Quote of the Day) operating across 10 distinct TCP and UDP network ports.

### 1. Inbound Listening Sockets and Denial-of-Service Vulnerabilities on PAWs
Operating legacy testing daemons on a dedicated administrative endpoint creates critical security liabilities:
* **UDP Reflection and Amplification DDoS**: UDP-based protocols in `simptcp` (such as Chargen on port 19 and Echo on port 7) respond to unauthenticated datagrams with substantial data amplification. Attackers can forge packets from the PAW's IP address or weaponize the PAW's network stack to flood target systems or participate in internal denial-of-service floods (MITRE ATT&CK T1498.002 - Network Denial of Service: Reflection Amplification).
* **Resource Starvation via Loop Conditions**: Faked packets bounced between Echo and Chargen ports can induce perpetual loop flooding, exhausting network bandwidth and kernel thread buffers on the PAW (T1499 - Endpoint Denial of Service).
* **Unauthenticated Network Footprinting**: Active diagnostic listeners leak operating system state, host availability, and local clock readings without authentication or audit logging (T1046 - Network Service Discovery).

### 2. PAW Clean Source and Strict Port Closure
Under Microsoft's PAW security architecture:
* **Zero Inbound Listening Ports**: Privileged Access Workstations must operate with zero unauthenticated inbound network listeners. Tier 0 administrative hosts initiate outbound management connections (WinRM, HTTPS, RPC) toward managed infrastructure and must never accept incoming diagnostic connections.
* **Elimination of Obsolete Protocols**: Diagnostic protocols developed in the 1980s have no legitimate operational role on Tier 0 management assets.
* **Socket and Memory Footprint Reduction**: Disabling `simptcp` permanently closes listening sockets on ports 7, 9, 13, 17, and 19 (both TCP and UDP), hardening the PAW network perimeter.

### 3. MITRE ATT&CK Mapping
* **T1498.002 - Network Denial of Service: Reflection Amplification**: Weaponizing UDP ports 7 and 19 in denial-of-service attacks.
* **T1499 - Endpoint Denial of Service**: Inducing loop conditions that starve administrative system resources.
* **T1046 - Network Service Discovery**: Probing legacy test ports to profile administrative assets.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `simptcp` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Modern Diagnostic Tools**: Native network diagnostic commands (`Test-NetConnection`, `ping`) do not require Simple TCP/IP Services.
* **Clean Baseline Alignment**: Eliminates unauthenticated legacy network listeners from the Tier 0 perimeter.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Simple TCP/IP Services` (`simptcp`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawsimptcp.ps1](../implementation_scripts/Configure-DisablePawsimptcp.ps1)

```powershell
# Configure-DisablePawsimptcp.ps1
# Description: Disables the unnecessary Simple TCP/IP Services (simptcp) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Simple TCP/IP Services service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawsimptcpStatus.ps1](../audit_scripts/Get-PawsimptcpStatus.ps1)

```powershell
# Get-PawsimptcpStatus.ps1
# Description: Audits the startup configuration of Simple TCP/IP Services (simptcp) service on the local PAW system.

Write-Host "--- Auditing Simple TCP/IP Services (simptcp) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
