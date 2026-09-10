# [REQ-PAW-052] Disable World Wide Web Publishing Service for PAWs (W3SVC)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-052](../../08-endpoints/services/disable-w3svc.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\World Wide Web Publishing Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\W3SVC`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The World Wide Web Publishing Service (`W3SVC`) is the core engine for Internet Information Services (IIS), responsible for managing HTTP/HTTPS listeners, routing requests to `w3wp.exe` worker processes, and hosting web applications.

### 1. Inbound Web Services Attack Surface on Tier 0 Assets
Operating an inbound HTTP web server on a Privileged Access Workstation represents an unacceptable vulnerability profile:
* **Exposing Inbound Web Ports**: Binding TCP ports 80 and 443 on a PAW inverts the workstation's security model, opening listening sockets directly on the administrative network segment and exposing the machine to remote port scanners and automated vulnerability exploitation.
* **Web Exploits and Shell Injection**: Running web services introduces severe attack vectors, including remote code execution, directory traversal, unauthenticated file uploads, and web shell implantation (MITRE ATT&CK T1505.003 - Server Software Component: Web Shell). An adversary achieving code execution in an IIS worker process can exploit local privilege escalation vulnerabilities to extract Tier 0 Domain Admin credentials from LSASS.
* **Kernel Driver Vulnerabilities (`HTTP.sys`)**: IIS utilizes the kernel-mode driver `HTTP.sys` to process incoming packets. Unauthenticated remote vulnerabilities in `HTTP.sys` (such as buffer overflows and memory corruption flaws) allow remote adversaries to execute code with ring 0 kernel privileges without requiring valid authentication credentials.

### 2. PAW Clean Source and Single-Purpose Principle
Privileged Access Workstations are dedicated to the administration of Tier 0 directory and identity systems:
* **Strict Directional Demarcation**: PAWs must operate strictly under the clean source principle, initiating outbound management connections (such as WinRM, RPC over Kerberos, and HTTPS) toward managed servers. PAWs must never function as web servers or process inbound client connections.
* **Resource and Attack Surface Minimization**: Disabling `W3SVC` ensures that the IIS process stack, application pools, and listening network ports are completely removed from the workstation.

### 3. MITRE ATT&CK Mapping
* **T1190 - Exploit Public-Facing Application**: Exploiting vulnerabilities in web server components or the `HTTP.sys` kernel driver.
* **T1505.003 - Server Software Component: Web Shell**: Planting web shells on endpoints to execute arbitrary commands and establish persistence.
* **T1074 - Data Staged**: Staging tools and extracted administrative credentials within an unauthorized local web directory.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `W3SVC` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Web-Based Administrative Consoles**: Accessing web-based management consoles on remote servers (e.g., Active Directory Certificate Services web enrollment, out-of-band iLO/iDRAC consoles) requires only an outbound browser client and is completely unaffected.
* **Zero Listening Ports**: Enforces the PAW security standard requiring zero inbound network listeners.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `World Wide Web Publishing Service` (`W3SVC`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawW3SVC.ps1](../implementation_scripts/Configure-DisablePawW3SVC.ps1)

```powershell
# Configure-DisablePawW3SVC.ps1
# Description: Disables the unnecessary World Wide Web Publishing Service (W3SVC) service on the local PAW.

Write-Host "Applying hardening requirement: Disable World Wide Web Publishing Service service on PAW..." -ForegroundColor Cyan

$ServiceName = "W3SVC"
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

[Download Script: Get-PawW3SVCStatus.ps1](../audit_scripts/Get-PawW3SVCStatus.ps1)

```powershell
# Get-PawW3SVCStatus.ps1
# Description: Audits the startup configuration of World Wide Web Publishing Service (W3SVC) service on the local PAW system.

Write-Host "--- Auditing World Wide Web Publishing Service (W3SVC) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "W3SVC"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.43 (W3SVC)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
