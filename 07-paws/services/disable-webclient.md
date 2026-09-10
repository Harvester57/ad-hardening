# [REQ-PAW-166] Disable WebClient Service for PAWs (WebClient)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-177](../../08-endpoints/services/disable-webclient.md); for Domain Controllers, refer to [REQ-DC-146](../../02-domain-controllers/services/disable-webclient.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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
The WebClient service (`WebClient`, driven by `davclnt.sys`) handles Web Distributed Authoring and Versioning (WebDAV) file requests over HTTP and HTTPS.

### 1. Eliminating WebDAV Coercion and Tier 0 Credential Relaying
Privileged Access Workstations host the most sensitive credentials in the enterprise, including Domain Admin, Enterprise Admin, and Tier 0 computer account tokens. Leaving the WebClient service enabled exposes these critical credentials to catastrophic cross-protocol relay attacks:
* **The WebDAV Coercion Vector**: Adversaries can induce outbound authentication from the PAW by leveraging RPC coercion techniques (such as PetitPotam, DFSCoerce, or ShadowCoerce) or enticing administrators to interact with crafted shortcuts or UNC paths specifying WebDAV syntax (e.g., `\\attacker@80\share\test`).
* **Bypassing SMB Signing Safeguards**: While enterprise hardening enforces SMB signing across Tier 0 infrastructure to prevent SMB relaying, WebDAV forces authentication over **HTTP/HTTPS**. HTTP authentication does not enforce SMB message signing, allowing attackers capturing the coerced NTLM authentication to relay it immediately to internal directory endpoints.
* **Catastrophic Directory Takeover**: An attacker who relays a coerced Tier 0 PAW machine account or Domain Admin credential to Active Directory Certificate Services (AD CS) Web Enrollment (ESC8) can enroll a certificate on behalf of the administrator, achieving immediate and total domain compromise. Relaying to Domain Controller LDAP interfaces allows attackers to inject shadow credentials or configure resource-based delegation.

### 2. PAW Clean Source and Strict Isolation Requirements
Under Microsoft's Privileged Access Workstation architecture:
* **Clean Source Demarcation**: PAWs are dedicated solely to directory and infrastructure administration. Administrative workflows are executed exclusively via encrypted, authenticated enterprise protocols (WinRM, HTTPS, Kerberos-authenticated RPC). PAWs must never mount or interact with remote WebDAV shares.
* **Neutralizing the Redirector**: Disabling the WebClient service prevents `davclnt.sys` from executing and permanently eliminates the operating system's ability to initiate outbound WebDAV HTTP authentication handshakes.

### 3. MITRE ATT&CK Mapping
* **T1187 - Forced Authentication**: Coercing Tier 0 administrative endpoints to authenticate over HTTP via WebDAV UNC paths.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Relaying coerced Tier 0 credentials to AD CS and LDAP.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Accessing network shares and redirectors across enterprise boundaries.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling the WebClient service is completely transparent for all Active Directory administration, server management tools (RSAT), PowerShell remoting, and Hyper-V management.
* **WebDAV Mapping Blocked**: Mapping WebDAV web folders in Windows Explorer is blocked, which represents the required baseline configuration for Tier 0 administrative hosts.
* **Directory Hardening Alignment**: Synchronizes the PAW baseline with Domain Controller hardening ([REQ-DC-146](../../02-domain-controllers/services/disable-webclient.md)), eliminating WebDAV coercion vectors across all Tier 0 assets.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `WebClient`, double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawWebClient.ps1](../implementation_scripts/Configure-DisablePawWebClient.ps1)

```powershell
# Configure-DisablePawWebClient.ps1
# Description: Disables the unnecessary WebClient service on the local PAW system.

Write-Host "Applying hardening requirement: Disable WebClient service on PAW..." -ForegroundColor Cyan

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

*To verify the startup configuration of the WebClient service on the PAW:*

[Download Script: Get-PawWebClientStatus.ps1](../audit_scripts/Get-PawWebClientStatus.ps1)

```powershell
# Get-PawWebClientStatus.ps1
# Description: Audits the startup configuration of the WebClient service on the local PAW system.

Write-Host "--- Auditing WebClient Service on PAW ---" -ForegroundColor Cyan

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
* **CIS Microsoft Windows Client Benchmark**: System service minimization guidelines
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on administrative systems
* **DoD Windows 11 Computer STIG**: Unnecessary system services restrictions
