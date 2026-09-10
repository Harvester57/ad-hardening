# [REQ-END-041] Disable Microsoft FTP Service (FTPSVC)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-041](../../07-paws/services/disable-ftpsvc.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Microsoft FTP Service` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\FTPSVC`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Microsoft FTP Service (`FTPSVC`) is an IIS server component that provides File Transfer Protocol (FTP) hosting services over TCP port 21.

### 1. Inherent Insecurity of Cleartext FTP and Remote Staging
Operating an FTP server daemon on general client workstations or standard member servers introduces critical security risks:
* **Cleartext Authentication and Sniffing**: Standard FTP transmits user authentication commands (`USER` and `PASS`) and file payloads entirely in cleartext. Any adversary positioned on the local network segment or routing transit path can sniff plaintext credentials, compromising domain user or administrative accounts (MITRE ATT&CK T1557 - Adversary-in-the-Middle).
* **Malicious Ingress and Tool Staging**: Adversaries who gain access to an endpoint frequently enable or abuse local FTP services to establish unauthorized file drop locations for staging secondary exploit tools, lateral movement binaries, and post-exploitation scripts without passing through web proxies or email security filters (T1074 - Data Staged).
* **Data Exfiltration Channel**: An unmonitored FTP listener provides adversaries and rogue insiders with an unencrypted conduit to aggregate and exfiltrate confidential enterprise data, circumventing data loss prevention (DLP) and deep packet inspection systems (T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol).

### 2. Enterprise Demarcation and Least Functionality
In enterprise Active Directory environments:
* File transfers and sharing must be conducted via authenticated and cryptographically protected protocols, such as SMB 3.1.1 (with mutual authentication and AES-GCM encryption), HTTPS REST endpoints, or enterprise SFTP infrastructure.
* Workstations and standard servers must never host unencrypted FTP server daemons. Disabling `FTPSVC` closes TCP port 21 and eliminates an unauthenticated file hosting listener.

### 3. MITRE ATT&CK Mapping
* **T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol**: Exfiltrating sensitive corporate files over unencrypted FTP channels.
* **T1074 - Data Staged**: Establishing unauthorized local staging repositories for malicious binaries and collected data.
* **T1557 - Adversary-in-the-Middle**: Capturing plaintext credentials during unencrypted FTP authentication sessions.

---

## Legacy Impact & Compatibility
* **Outbound FTP Client Connections**: Disabling `FTPSVC` does **not** restrict outbound FTP client connections (e.g., using command-line `ftp.exe`, WinSCP, or FileZilla to connect to external servers).
* **Enterprise File Shares**: Access to Active Directory SMB file shares (`\\domain\share`), Distributed File System (DFS) namespaces, SharePoint, and OneDrive operates without interruption.
* **Secure File Transfer Standards**: Organizations with legitimate file transfer requirements must deploy dedicated SFTP (SSH File Transfer Protocol) or HTTPS appliances with central auditing rather than enabling unencrypted FTP on endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Microsoft FTP Service` (`FTPSVC`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableFTPSVC.ps1](../implementation_scripts/Configure-DisableFTPSVC.ps1)

```powershell
# Configure-DisableFTPSVC.ps1
# Description: Disables the unnecessary Microsoft FTP Service (FTPSVC) service.

Write-Host "Applying hardening requirement: Disable Microsoft FTP Service service..." -ForegroundColor Cyan

$ServiceName = "FTPSVC"
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

[Download Script: Get-FTPSVCStatus.ps1](../audit_scripts/Get-FTPSVCStatus.ps1)

```powershell
# Get-FTPSVCStatus.ps1
# Description: Audits the startup configuration of Microsoft FTP Service (FTPSVC) service.

Write-Host "--- Auditing Microsoft FTP Service (FTPSVC) Service ---" -ForegroundColor Cyan

$ServiceName = "FTPSVC"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.12 (FTPSVC)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
