# [REQ-END-177] Disable WebClient Service (WebClient)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled.

The WebClient service handles Web Distributed Authoring and Versioning (WebDAV) file requests over HTTP/HTTPS. In an Active Directory environment, leaving the WebClient service enabled on endpoints introduces significant risk:
1. **WebDAV Credential Coercion**: Attackers on the internal network can coerce endpoint authentication via WebDAV UNC paths (e.g., `\\attacker@80\share\path`). The endpoint sends NTLM authentication over HTTP.
2. **Bypassing SMB Signing**: Because HTTP authentication does not enforce SMB signing, coerced NTLM authentication from the endpoint can be relayed to internal directory services (such as LDAP/LDAPS, AD CS Web Enrollment, or other servers), facilitating lateral movement and privilege escalation.

Disabling the WebClient service on standard endpoints and servers closes this attack vector while minimizing unnecessary background resource consumption.

---

## Legacy Impact & Compatibility
* **WebDAV Mapping Blocked**: Users will not be able to connect to remote WebDAV web folders directly using Windows Explorer drive mappings.
* **SharePoint / Modern Cloud Storage**: Modern SharePoint Online and OneDrive sync clients use native REST APIs and do not require the legacy WebClient service.
* **Engineering Exceptions**: If specific legacy applications require WebDAV connectivity, create a targeted GPO exclusion for those systems while maintaining the baseline across standard workstations.

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
