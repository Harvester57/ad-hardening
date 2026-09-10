# [REQ-END-049] Disable Web Management Service (WMSvc)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-049](../../07-paws/services/disable-wmsvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Web Management Service (`WMSvc`) facilitates remote web server administration for Internet Information Services (IIS), listening for incoming remote management connections over HTTPS TCP port 8172.

### 1. Inbound Management Port Exposure and Exploitation
Operating a remote web management daemon on standard client endpoints introduces critical security exposures:
* **Persistent Inbound Management Listener (TCP 8172)**: Enabling `WMSvc` binds an unmanaged HTTPS listening socket on TCP port 8172. Exposing administrative web listeners across client subnets inverts the endpoint security model, subjecting workstations to automated network discovery, password spraying, and brute-force credential stuffing (MITRE ATT&CK T1110 - Brute Force).
* **Remote Management Handler Exploits**: Remote management requests are handled by IIS management modules. Flaws in request deserialization, TLS handshake handling, or authentication delegation in `WMSvc` expose endpoints to denial of service or remote code execution vulnerabilities (T1190 - Exploit Public-Facing Application).
* **Principle of Least Functionality**: Workstations and standard member servers should never host IIS web servers or expose remote web administration services. Maintaining an active management daemon on client machines provides zero enterprise value while creating an unnecessary attack surface.

### 2. Enterprise Demarcation and Least Privilege
In enterprise Active Directory architectures:
* Remote web administration must be confined to dedicated web servers located in secured DMZ or server segments, protected by network access control lists and multifactor authentication.
* Disabling `WMSvc` ensures that workstations cannot inadvertently expose remote web administration endpoints to the local network segment.

### 3. MITRE ATT&CK Mapping
* **T1190 - Exploit Public-Facing Application**: Exploiting vulnerabilities in remote web management services.
* **T1110 - Brute Force**: Automated credential spraying against exposed remote administrative web listeners.
* **T1046 - Network Service Discovery**: Adversary network scanning to locate active remote administrative ports on internal hosts.

---

## Legacy Impact & Compatibility
* **Client IIS Management Tools**: Disabling the local `WMSvc` server service does **not** prevent administrators from launching the IIS Manager console (`inetmgr.exe`) on the workstation to remotely manage authorized production web servers via outbound HTTPS.
* **Modern Windows Administration**: Native enterprise remote administration tools (Windows Admin Center, WinRM, PowerShell Remoting, WMI) operate independently and function without interruption.
* **Zero Inbound Port Footprint**: Guarantees TCP port 8172 remains closed across the entire enterprise endpoint fleet.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Web Management Service` (`WMSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableWMSvc.ps1](../implementation_scripts/Configure-DisableWMSvc.ps1)

```powershell
# Configure-DisableWMSvc.ps1
# Description: Disables the unnecessary Web Management Service (WMSvc) service.

Write-Host "Applying hardening requirement: Disable Web Management Service service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-WMSvcStatus.ps1](../audit_scripts/Get-WMSvcStatus.ps1)

```powershell
# Get-WMSvcStatus.ps1
# Description: Audits the startup configuration of Web Management Service (WMSvc) service.

Write-Host "--- Auditing Web Management Service (WMSvc) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
