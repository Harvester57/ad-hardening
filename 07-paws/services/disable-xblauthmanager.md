# [REQ-PAW-054] Disable Xbox Live Auth Manager for PAWs (XblAuthManager)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-054](../../08-endpoints/services/disable-xblauthmanager.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
The Xbox Live Auth Manager (`XblAuthManager`, hosted in `svchost.exe` via `XblAuthManager.dll`) provides programmatic token brokering and identity authentication services for consumer Microsoft Accounts (MSA) and the Xbox Live ecosystem.

### 1. Enforcement of Clean Source Principle and Tier 0 Identity Isolation
Under Microsoft Privileged Access Workstation guidelines, administrative workstations used for Tier 0 Active Directory administration must adhere to absolute identity separation:
* **Strict Tier 0 Identity Boundaries**: PAWs must authenticate exclusively against authoritative internal Active Directory Domain Controllers and dedicated Tier 0 administrative interfaces. Introducing consumer identity brokers allows consumer Microsoft Accounts (MSA) to be cached, authenticated, or brokered on administrative systems.
* **Credential Contamination and Side-Channel Leakage**: Consumer authentication brokers interface with the Windows Web Account Manager (WAM) and cache authentication tokens in user profile vaults. Mixing consumer identity tokens with Tier 0 administrative credentials on the same workstation introduces cross-boundary contamination and violates the Clean Source Principle.

### 2. Elimination of Unsanctioned Outbound Cloud Telemetry
* An active `XblAuthManager` attempts outbound HTTPS connections to consumer Xbox Live authentication endpoints (`*.auth.xboxlive.com`).
* PAW network perimeters enforce strict, deterministic egress rules allowing outbound traffic only to specific Tier 0 assets (Domain Controllers, internal PKI, administrative jump hosts). Outbound connections to consumer cloud endpoints represent unauthorized egress and complicate network anomaly auditing.

### 3. Absolute Least Functionality on Tier 0 Assets
* Privileged administrative tasks (Active Directory management, DNS configuration, PKI administration) have zero requirement for consumer gaming identity services.
* Disabling the service ensures that unnecessary authentication brokers remain completely inert, reducing the surface area for local token harvesting and privilege escalation.

### 4. MITRE ATT&CK Mapping
* **T1078 - Valid Accounts**: Preventing unauthorized consumer identity token caching and credential confusion on Tier 0 administrative systems.
* **T1071.001 - Application Layer Protocol: Web Protocols**: Preventing unauthorized outbound web connections from administrative workstations to consumer cloud services.
* **T1556 - Modify Authentication Process**: Enforcing strictly vetted, local Kerberos and smart card authentication pipelines.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `XblAuthManager` is completely transparent to all Tier 0 management tasks, including RSAT, PowerShell Remoting, Active Directory Administrative Center, GPMC, and administrative smart card authentication.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on Xbox Live authentication services on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Auth Manager` (`XblAuthManager`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawXblAuthManager.ps1](../implementation_scripts/Configure-DisablePawXblAuthManager.ps1)

```powershell
# Configure-DisablePawXblAuthManager.ps1
# Description: Disables the unnecessary Xbox Live Auth Manager (XblAuthManager) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Xbox Live Auth Manager service on PAW..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service on the PAW:*

[Download Script: Get-PawXblAuthManagerStatus.ps1](../audit_scripts/Get-PawXblAuthManagerStatus.ps1)

```powershell
# Get-PawXblAuthManagerStatus.ps1
# Description: Audits the startup configuration of Xbox Live Auth Manager (XblAuthManager) service on the local PAW system.

Write-Host "--- Auditing Xbox Live Auth Manager (XblAuthManager) Service on PAW ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
