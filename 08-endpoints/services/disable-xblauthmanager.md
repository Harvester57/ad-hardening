# [REQ-END-054] Disable Xbox Live Auth Manager (XblAuthManager)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-054](../../07-paws/services/disable-xblauthmanager.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Xbox Live Auth Manager` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Xbox Live Auth Manager (`XblAuthManager`, hosted in `svchost.exe` via `XblAuthManager.dll`) provides programmatic authentication and token brokering services for consumer Microsoft Accounts (MSA) and the Xbox Live cloud gaming platform.

### 1. Infiltration of Consumer Identity into Enterprise Workstations
Enterprise endpoints must authenticate strictly against authoritative enterprise identity providers—namely Active Directory Domain Services (Kerberos / NTLMv2) and Microsoft Entra ID (Azure AD):
* **Consumer Token Brokering**: `XblAuthManager` interfaces with Windows Web Account Manager (WAM) to issue, renew, and cache OAuth 2.0 / Xbox Secure Token Service (XSTS) tokens associated with consumer Microsoft Accounts (`login.live.com`).
* **Identity Confusion and Shadow IT**: Permitting personal gaming identity brokers on corporate systems blurs the boundary between corporate and personal assets. Users may inadvertently or deliberately link personal consumer accounts, leading to unvetted cloud synchronization and bypassing enterprise single sign-on (SSO) and Conditional Access policies.

### 2. Unsanctioned Outbound Telemetry and Cloud Connections
* When enabled, `XblAuthManager` regularly establishes outbound HTTPS connections to consumer Xbox endpoints (`*.auth.xboxlive.com`, `user.auth.xboxlive.com`).
* These connections transmit device telemetry, network identifiers, and user metadata to consumer cloud endpoints. Uncontrolled outbound communication creates noise in enterprise SIEM telemetry, frustrates network proxy monitoring, and expands the external communication surface.

### 3. Least Functionality in Corporate Workstations
* Gaming authentication has zero legitimate utility on enterprise client workstations or member servers.
* Disabling `XblAuthManager` aligns with CIS Microsoft Windows Client Benchmarks and the principle of least functionality (NIST SP 800-53 CM-7), ensuring consumer identity mechanisms are dormant.

### 4. MITRE ATT&CK Mapping
* **T1078 - Valid Accounts**: Mitigating credential confusion and unauthorized consumer cloud token caching on corporate workstations.
* **T1071.001 - Application Layer Protocol: Web Protocols**: Preventing unauthorized outbound HTTPS traffic to consumer authentication endpoints.
* **T1556 - Modify Authentication Process**: Restricting local authentication flows to approved enterprise identity brokers.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `XblAuthManager` is completely transparent to Active Directory domain authentication, Kerberos ticket granting, Entra ID hybrid join, Microsoft 365 apps (Office, Outlook, Teams), and corporate Line-of-Business (LOB) software.
* **Consumer Gaming Applications**: Microsoft Store games, Xbox Game Bar, and consumer Xbox applications that require Xbox Live authentication will be unable to log in, fetch cloud gamertags, or retrieve achievements on hardened enterprise workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Auth Manager` (`XblAuthManager`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableXblAuthManager.ps1](../implementation_scripts/Configure-DisableXblAuthManager.ps1)

```powershell
# Configure-DisableXblAuthManager.ps1
# Description: Disables the unnecessary Xbox Live Auth Manager (XblAuthManager) service.

Write-Host "Applying hardening requirement: Disable Xbox Live Auth Manager service..." -ForegroundColor Cyan

$ServiceName = "XblAuthManager"
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

[Download Script: Get-XblAuthManagerStatus.ps1](../audit_scripts/Get-XblAuthManagerStatus.ps1)

```powershell
# Get-XblAuthManagerStatus.ps1
# Description: Audits the startup configuration of Xbox Live Auth Manager (XblAuthManager) service.

Write-Host "--- Auditing Xbox Live Auth Manager (XblAuthManager) Service ---" -ForegroundColor Cyan

$ServiceName = "XblAuthManager"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.45 (XblAuthManager)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
