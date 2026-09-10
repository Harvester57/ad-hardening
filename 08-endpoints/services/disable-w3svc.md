# [REQ-END-052] Disable World Wide Web Publishing Service (W3SVC)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-052](../../07-paws/services/disable-w3svc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The World Wide Web Publishing Service (`W3SVC`) is the core Internet Information Services (IIS) HTTP/HTTPS web server engine. It manages HTTP listeners, routes web traffic to `w3wp.exe` worker processes, and hosts ASP.NET, PHP, and static web content over TCP ports 80 and 443.

### 1. Inbound Web Server Attack Surface on Client Endpoints
Running a web server on general client workstations or standard member servers fundamentally compromises endpoint security:
* **Persistent Inbound HTTP/HTTPS Listeners**: Enabling `W3SVC` binds ports 80 and 443, converting an endpoint into an accessible network web server. This inverts the client security model, exposing the endpoint to continuous network port scanning, web application scanning, and automated exploit delivery.
* **Web Exploitation Vectors and Web Shells**: Web servers are subject to critical exploitation techniques, including path traversal, arbitrary file uploads, unauthenticated Server-Side Request Forgery (SSRF), and the injection of persistent web shells (MITRE ATT&CK T1505.003 - Server Software Component: Web Shell). An adversary establishing a web shell on an endpoint can execute arbitrary commands with the privileges of the IIS Application Pool identity or `NT AUTHORITY\SYSTEM`.
* **Kernel-Mode HTTP.sys Exploits**: IIS relies on the Windows kernel driver `HTTP.sys` to process incoming HTTP requests. Flaws in `HTTP.sys` (such as historical integer overflows CVE-2015-1635 / MS15-034 and remote code execution vulnerabilities CVE-2022-21907) allow unauthenticated attackers to trigger remote code execution or cause kernel blue-screen crashes with a single malformed HTTP request.
* **Malicious Payload Staging**: Compromised endpoints with active web servers can be weaponized by adversaries as internal distribution points to host malicious binaries, phishing payloads, and lateral movement tools within the corporate network (T1074 - Data Staged).

### 2. Least Functionality and Infrastructure Separation
In enterprise architecture:
* Web hosting is strictly restricted to designated, hardened web servers situated in segmented DMZs or application enclaves.
* Client workstations and standard member servers must never host web applications. Disabling `W3SVC` eliminates the IIS worker process footprint, closes TCP ports 80 and 443, and removes critical exploit vectors.

### 3. MITRE ATT&CK Mapping
* **T1190 - Exploit Public-Facing Application**: Exploiting vulnerabilities in web applications or the underlying `HTTP.sys` stack.
* **T1505.003 - Server Software Component: Web Shell**: Deploying web shells into web roots to maintain persistence and execute commands.
* **T1074 - Data Staged**: Using an unauthorized local web server to stage malicious files and tools for internal propagation.

---

## Legacy Impact & Compatibility
* **Web Browsing**: Disabling `W3SVC` does **not** restrict outbound web browsing. Users can continue browsing HTTP/HTTPS websites using Edge, Chrome, or Firefox without any impact.
* **Client Applications**: Standard client line-of-business software, REST API clients, and cloud productivity tools (Microsoft 365, OneDrive) communicate as clients and do not require local IIS hosting.
* **Developer Workstations**: If software engineers require local IIS for development, they should be isolated into a dedicated developer OU with host firewall restrictions, or transitioned to user-mode development servers (e.g., IIS Express, Docker desktop containers, or Kestrel). Standard corporate workstations must keep `W3SVC` disabled.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `World Wide Web Publishing Service` (`W3SVC`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableW3SVC.ps1](../implementation_scripts/Configure-DisableW3SVC.ps1)

```powershell
# Configure-DisableW3SVC.ps1
# Description: Disables the unnecessary World Wide Web Publishing Service (W3SVC) service.

Write-Host "Applying hardening requirement: Disable World Wide Web Publishing Service service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-W3SVCStatus.ps1](../audit_scripts/Get-W3SVCStatus.ps1)

```powershell
# Get-W3SVCStatus.ps1
# Description: Audits the startup configuration of World Wide Web Publishing Service (W3SVC) service.

Write-Host "--- Auditing World Wide Web Publishing Service (W3SVC) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
