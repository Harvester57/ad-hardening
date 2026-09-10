# [REQ-PAW-056] Disable Xbox Live Networking Service for PAWs (XboxNetApiSvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-056](../../08-endpoints/services/disable-xboxnetapisvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
The Xbox Live Networking Service (`XboxNetApiSvc`, hosted in `svchost.exe` via `XboxNetApiSvc.dll`) provides network interface abstraction, peer-to-peer session negotiation, and Teredo NAT traversal tunneling for consumer gaming applications.

### 1. Enforcement of Clean Source Principle and Strict Network Perimeter Boundaries
Under Microsoft Privileged Access Workstation guidelines, Tier 0 workstations must enforce strictly deterministic, audited, and isolated network communications:
* **Prohibition of Protocol Tunneling**: `XboxNetApiSvc` manages and activates Teredo IPv6-in-UDP encapsulation (RFC 4380) over UDP port 3544. Protocol tunneling encapsulates network packets inside UDP datagrams, allowing outbound and inbound traffic to bypass network perimeter inspection, stateful firewall rules, and intrusion detection systems. On a PAW, any form of protocol tunneling is a severe compromise of network isolation.
* **Prohibition of Inbound Peer-to-Peer Connections**: Teredo establishes keep-alive states with external relay servers to enable unsolicited inbound connections from arbitrary external hosts. Permitting unvetted external peers to initiate inbound UDP traffic to a Tier 0 administrative machine represents an unacceptable exposure of the management plane.

### 2. Elimination of Peer-to-Peer Attack Surface and Socket Handling
* Real-time peer-to-peer networking code for multiplayer gaming and voice chat processes untrusted network packets with minimal transport verification.
* Running peer-to-peer socket handlers on administrative workstations creates unnecessary attack surface for remote memory corruption, socket exhaustion, and denial-of-service exploits.

### 3. Absolute Least Functionality on Tier 0 Assets
* Administration of Domain Controllers, Active Directory Federation Services, and Tier 0 PKI relies exclusively on deterministic protocols (Kerberos, LDAP/S, SMB signing, WinRM, RPC over IPSec).
* Disabling `XboxNetApiSvc` permanently disables the Teredo network interface and peer-to-peer gaming APIs on Tier 0 systems.

### 4. MITRE ATT&CK Mapping
* **T1572 - Protocol Tunneling**: Preventing unauthorized Teredo IPv6-over-UDP tunneling from circumventing Tier 0 network isolation boundaries.
* **T1046 - Network Service Discovery**: Preventing external discovery of administrative hosts via Teredo relay keep-alives.
* **T1210 - Exploitation of Remote Services**: Neutralizing vulnerabilities in peer-to-peer packet handling routines.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `XboxNetApiSvc` is completely transparent to all Tier 0 management tasks, including RSAT, PowerShell Remoting, Active Directory Administrative Center, GPMC, VPN tunnels, and IPsec encrypted administrative management paths.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on Xbox Live networking services on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Networking Service` (`XboxNetApiSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawXboxNetApiSvc.ps1](../implementation_scripts/Configure-DisablePawXboxNetApiSvc.ps1)

```powershell
# Configure-DisablePawXboxNetApiSvc.ps1
# Description: Disables the unnecessary Xbox Live Networking Service (XboxNetApiSvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Xbox Live Networking Service service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawXboxNetApiSvcStatus.ps1](../audit_scripts/Get-PawXboxNetApiSvcStatus.ps1)

```powershell
# Get-PawXboxNetApiSvcStatus.ps1
# Description: Audits the startup configuration of Xbox Live Networking Service (XboxNetApiSvc) service on the local PAW system.

Write-Host "--- Auditing Xbox Live Networking Service (XboxNetApiSvc) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
