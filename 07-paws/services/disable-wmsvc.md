# [REQ-PAW-049] Disable Web Management Service for PAWs (WMSvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-049](../../08-endpoints/services/disable-wmsvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Web Management Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\WMSvc`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Web Management Service (`WMSvc`) enables remote web server management for Internet Information Services (IIS), listening for incoming remote connections over HTTPS TCP port 8172.

### 1. Inbound Management Listeners on Administrative Workstations
Operating a remote web management daemon on a Tier 0 Privileged Access Workstation represents an unacceptable security risk:
* **Inbound Management Socket Exposure**: Enabling `WMSvc` opens a listening socket on TCP port 8172. Inbound administrative listeners on a PAW expose the host to network enumeration, password spraying, and brute-force credential stuffing from lower-tier network zones (MITRE ATT&CK T1110 - Brute Force).
* **Remote Management Handler Exploits**: Web management requests are processed by IIS management components. Flaws in handler parsing, request deserialization, or TLS processing could be exploited by an adversary to achieve remote code execution on the administrative endpoint (T1190 - Exploit Public-Facing Application).

### 2. PAW Clean Source and Directional Isolation Requirements
Under Microsoft's Privileged Access Workstation architecture:
* **Administrative Flow Directionality**: PAWs are strictly administrative sources. Administrative management flows exclusively **outbound** from the PAW toward managed servers (using secure WinRM, HTTPS, and Kerberos-authenticated RPC). Inbound administrative access to a PAW from external systems is strictly prohibited.
* **Credential Protection**: Opening an inbound administrative web listener creates an avenue for lateral movement into the PAW. If compromised, an adversary can access the LSASS process space and extract cached Tier 0 Domain Admin credentials.
* **Socket and Surface Reduction**: Disabling `WMSvc` guarantees that TCP port 8172 remains closed and prevents any IIS management daemon from executing in the background.

### 3. MITRE ATT&CK Mapping
* **T1190 - Exploit Public-Facing Application**: Exploiting remote web management daemons to gain code execution.
* **T1110 - Brute Force**: Automated credential attacks targeting listening administrative web interfaces.
* **T1046 - Network Service Discovery**: Adversaries scanning management subnets to locate active administrative listeners.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `WMSvc` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Outbound Management Consoles**: Tier 0 administrators can continue launching client administration consoles (such as IIS Manager or Windows Admin Center) to remotely manage production servers over outbound secure connections.
* **Perimeter Defense**: Confirms that no inbound management web ports remain open on the PAW.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Web Management Service` (`WMSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawWMSvc.ps1](../implementation_scripts/Configure-DisablePawWMSvc.ps1)

```powershell
# Configure-DisablePawWMSvc.ps1
# Description: Disables the unnecessary Web Management Service (WMSvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Web Management Service service on PAW..." -ForegroundColor Cyan

$ServiceName = "WMSvc"
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

[Download Script: Get-PawWMSvcStatus.ps1](../audit_scripts/Get-PawWMSvcStatus.ps1)

```powershell
# Get-PawWMSvcStatus.ps1
# Description: Audits the startup configuration of Web Management Service (WMSvc) service on the local PAW system.

Write-Host "--- Auditing Web Management Service (WMSvc) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "WMSvc"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.34 (WMSvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
