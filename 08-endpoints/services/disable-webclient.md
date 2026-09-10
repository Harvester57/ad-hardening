# [REQ-END-177] Disable WebClient Service (WebClient)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-166](../../07-paws/services/disable-webclient.md); for Domain Controllers, refer to [REQ-DC-146](../../02-domain-controllers/services/disable-webclient.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\WebClient` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\WebClient`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The WebClient service (`WebClient`, driven by `davclnt.sys`) enables Windows programs to create, access, and modify remote files on Internet-based web servers using the Web Distributed Authoring and Versioning (WebDAV) protocol over HTTP and HTTPS.

### 1. WebDAV Credential Coercion and Cross-Protocol NTLM Relaying
In an Active Directory enterprise domain, the WebClient service represents one of the most critical lateral movement and privilege escalation attack surfaces:
* **The WebDAV Coercion Mechanism**: Adversaries leverage RPC coercion protocols (such as PetitPotam / MS-EFSR, DFSCoerce, ShadowCoerce, or PrinterBug / MS-RPRN) or social engineering (malicious `.lnk` shortcuts, email links, or office documents) targeting a WebDAV UNC path (e.g., `\\attacker.domain@80\share\test` or `\\attacker.domain@SSL@443\share`).
* **Bypassing SMB Signing**: When Windows accesses a standard SMB path (`\\server\share`), the SMB redirector enforces SMB signing (if configured), which cryptographically prevents relaying authentication to other SMB services. However, when the path specifies `@80` or `@SSL`, the Multiple UNC Provider (MUP) hands the request to the `WebClient` service, forcing the host to authenticate over **HTTP/HTTPS** using NTLM.
* **Catastrophic NTLM Relaying Targets**: Because HTTP authentication does not enforce SMB message signing, coerced NTLM authentication from the endpoint can be relayed in real time to critical internal directory infrastructure:
  1. **Active Directory Certificate Services (AD CS) Web Enrollment (ESC8)**: Relaying coerced credentials to unhardened HTTP enrollment endpoints allows attackers to request and receive administrative client authentication certificates, resulting in instant domain escalation.
  2. **Active Directory LDAP / LDAPS**: Relaying machine or user credentials to domain controller LDAP interfaces allows attackers to configure Resource-Based Constrained Delegation (RBCD) or inject `msDS-KeyCredentialLink` (Shadow Credentials) to take over the target computer account.
  3. **Internal Application Servers**: Relaying to web-based intranet applications, Microsoft Exchange, or internal APIs.

### 2. Perimeter Egress and Malware Staging
The WebClient service allows mounting remote WebDAV shares over standard HTTP (port 80) and HTTPS (port 443) outbound connections:
* Attackers use WebDAV to mount remote adversary-controlled file repositories directly into Windows Explorer, bypassing outbound SMB port 445 egress filtering at enterprise firewalls.
* Malicious scripts and droppers utilize WebDAV paths to execute payloads directly from remote web servers without saving intermediate files to the local disk, evading basic host-based detection.

### 3. MITRE ATT&CK Mapping
* **T1187 - Forced Authentication**: Coercing endpoints to transmit NTLM authentication over HTTP via WebDAV UNC paths.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Relaying coerced NTLM HTTP credentials to LDAP/LDAPS and AD CS Web Enrollment.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Accessing network shares and redirectors across enterprise boundaries.

---

## Legacy Impact & Compatibility
* **Windows Explorer WebDAV Mappings**: Users will not be able to map remote WebDAV web folders as drive letters directly in Windows Explorer.
* **Modern Cloud Collaboration (SharePoint & OneDrive)**: Modern SharePoint Online and OneDrive for Business utilize the Microsoft Graph API, REST protocols, and the dedicated OneDrive sync client (`OneDrive.exe`), completely independent of the legacy WebClient service.
* **Legacy WebDAV Applications**: If specific legacy document management systems require WebDAV transport, implement a dedicated GPO exception for those specific hosts with strict firewall egress controls, while enforcing the disabled state across all standard workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Endpoint GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `WebClient`, double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableEndWebClient.ps1](../implementation_scripts/Configure-DisableEndWebClient.ps1)

```powershell
# Configure-DisableEndWebClient.ps1
# Description: Disables the unnecessary WebClient service on standard client endpoints and member servers.

Write-Host "Applying hardening requirement: Disable WebClient service on Endpoint..." -ForegroundColor Cyan

$ServiceName = "WebClient"
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

*To verify the startup configuration of the WebClient service on the endpoint:*

[Download Script: Get-EndWebClientStatus.ps1](../audit_scripts/Get-EndWebClientStatus.ps1)

```powershell
# Get-EndWebClientStatus.ps1
# Description: Audits the startup configuration of the WebClient service on the local endpoint.

Write-Host "--- Auditing WebClient Service on Endpoint ---" -ForegroundColor Cyan

$ServiceName = "WebClient"
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
* **CIS Microsoft Windows Client Benchmark**: System services hardening guidelines
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services
* **DoD Windows 11 Computer STIG**: Unnecessary system services restrictions
