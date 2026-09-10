# [REQ-PAW-041] Disable Microsoft FTP Service for PAWs (FTPSVC)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-041](../../08-endpoints/services/disable-ftpsvc.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

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

### 1. Insecurity of Cleartext Protocols and Unauthenticated Ingress on PAWs
Operating an FTP daemon on a Tier 0 Privileged Access Workstation represents an severe architectural security vulnerability:
* **Cleartext Credential Exposure**: Standard FTP transmits credentials and session data across the network in plaintext. Any network actor on the administrative subnet could sniff credentials or inject traffic, compromising privileged administrative accounts (MITRE ATT&CK T1557 - Adversary-in-the-Middle).
* **Malicious File Staging and Ingress**: Adversaries attempting to pivot into Tier 0 infrastructure target unhardened file hosting services to stage malicious payloads, DLL search order hijacking components, and memory dump utilities directly onto administrative machines (T1074 - Data Staged).
* **Covert Exfiltration Conduit**: An active FTP listener provides a potential covert exfiltration path for sensitive directory data, including AD database snapshots (ntds.dit), Kerberos ticket caches, and cryptographic keys (T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol).

### 2. PAW Clean Source and Strict Listening Socket Elimination
Under Microsoft's PAW security model:
* **Clean Source Integrity**: Administrative workstations must never run inbound server daemons that accept untrusted network files or process cleartext authentication exchanges.
* **Unidirectional Administration**: All PAW interactions are outbound toward managed Tier 0 systems. Inbound file transfer listeners on a PAW completely violate network boundary separation.
* **Socket Closure**: Disabling `FTPSVC` guarantees that TCP port 21 remains closed, ensuring that no unauthorized file ingress or cleartext transport mechanisms can be activated on the workstation.

### 3. MITRE ATT&CK Mapping
* **T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol**: Exfiltrating sensitive administrative artifacts via cleartext FTP.
* **T1074 - Data Staged**: Staging offensive binaries and post-exploitation scripts on an administrative host.
* **T1557 - Adversary-in-the-Middle**: Sniffing plaintext authentication credentials across local network segments.

---

## Legacy Impact & Compatibility
* **Tier 0 Administrative Management**: Disabling `FTPSVC` has zero impact on Active Directory administration, server management tools (RSAT), PowerShell remoting, or Hyper-V administration.
* **Administrative File Transfers**: Administrative scripts, tools, and updates should be deployed to PAWs through secure, cryptographically authenticated mechanisms (such as Group Policy Software Installation, Microsoft Endpoint Configuration Manager, or SMB 3.1.1 encrypted shares).
* **Perimeter Hardening**: Eliminates legacy cleartext protocols from the Tier 0 management perimeter.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Microsoft FTP Service` (`FTPSVC`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawFTPSVC.ps1](../implementation_scripts/Configure-DisablePawFTPSVC.ps1)

```powershell
# Configure-DisablePawFTPSVC.ps1
# Description: Disables the unnecessary Microsoft FTP Service (FTPSVC) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Microsoft FTP Service service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawFTPSVCStatus.ps1](../audit_scripts/Get-PawFTPSVCStatus.ps1)

```powershell
# Get-PawFTPSVCStatus.ps1
# Description: Audits the startup configuration of Microsoft FTP Service (FTPSVC) service on the local PAW system.

Write-Host "--- Auditing Microsoft FTP Service (FTPSVC) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
