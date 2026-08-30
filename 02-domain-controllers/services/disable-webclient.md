# [REQ-DC-146] Disable WebClient Service (WebClient)

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs) running Windows Server.
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Start`

---

## Rationale
The WebClient service enables Windows-based programs to create, access, and modify Internet-based files via the Web Distributed Authoring and Versioning (WebDAV) protocol.

In an Active Directory environment, the WebClient service represents a major credential coercion and relay attack surface:
1. **Bypassing SMB Signing**: WebDAV coercion triggers an outbound HTTP/HTTPS connection using NTLM authentication rather than SMB. Because HTTP authentication does not enforce SMB signing, an attacker can coerce a Domain Controller (e.g., via PetitPotam, DFSCoerce, or ShadowCoerce targeting a WebDAV path like `\\attacker@80\share\test`) and relay the coerced machine account NTLM credentials directly to LDAP/LDAPS, Active Directory Certificate Services (AD CS) Web Enrollment, or other critical directory endpoints.
2. **Principle of Least Functionality**: Domain Controllers perform core directory and authentication functions and must never operate as WebDAV clients to external or internal web servers.

Stopping and disabling the WebClient service on Domain Controllers completely neutralizes WebDAV-based coercion and cross-protocol relay vectors.

---

## Legacy Impact & Compatibility
* **No Directory Impact**: Disabling the WebClient service has zero impact on Active Directory Domain Services (AD DS), Kerberos authentication, replication, DNS, or Group Policy processing.
* **WebDAV Mapping Blocked**: Systems will not be able to map WebDAV shares via the Windows WebClient redirector. Domain Controllers should never mount external or internal WebDAV shares.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Domain Controllers GPO (e.g., `GPO_Hardening_DC`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `WebClient`, double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableWebClient.ps1](../implementation_scripts/Configure-DisableWebClient.ps1)

```powershell
# Configure-DisableWebClient.ps1
# Description: Disables the WebClient service on the Domain Controller to eliminate WebDAV coercion and relay attacks.

Write-Host "Applying hardening requirement: Disable WebClient service on Domain Controller..." -ForegroundColor Cyan

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

*To verify the startup configuration of the WebClient service on the Domain Controller:*

[Download Script: Get-WebClientStatus.ps1](../audit_scripts/Get-WebClientStatus.ps1)

```powershell
# Get-WebClientStatus.ps1
# Description: Audits the startup configuration of the WebClient service on the Domain Controller.

Write-Host "--- Auditing WebClient Service on Domain Controller ---" -ForegroundColor Cyan

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
* **ANSSI AD Hardening Guide**: Recommendations on host service minimization (R4) and coercion mitigation
* **CIS Microsoft Windows Server Benchmark**: Service minimization guidelines
* **DoD Windows Server STIG**: Disable unnecessary system services
