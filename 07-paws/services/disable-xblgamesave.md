# [REQ-PAW-055] Disable Xbox Live Game Save Service for PAWs (XblGameSave)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 client workstations and member servers, refer to baseline [REQ-END-055](../../08-endpoints/services/disable-xblgamesave.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\Xbox Live Game Save` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The Xbox Live Game Save Service (`XblGameSave`, hosted in `svchost.exe` via `XblGameSave.dll`) performs background synchronization of game save containers and application state to Microsoft Xbox Live consumer cloud infrastructure.

### 1. Enforcement of Clean Source Principle and Tier 0 Data Isolation
Under Microsoft Privileged Access Workstation guidelines, administrative workstations used for Tier 0 Active Directory administration must enforce strict single-purpose operational boundaries:
* **Zero Consumer Cloud Synchronization**: A Tier 0 PAW must never synchronize files or application data with consumer cloud storage platforms. Background synchronization daemons operating outside audited enterprise administrative logging introduce unauthorized egress paths.
* **Prevention of Covert Data Exfiltration**: In the event of a targeted attack or insider threat, unmonitored cloud synchronization services could be exploited as covert exfiltration vectors or staging mechanisms to move sensitive directory configuration scripts and cryptographic material out of the Tier 0 perimeter.

### 2. Elimination of Unsanctioned Background Processes and Egress Traffic
* PAWs operate under deterministic firewall rules where all outbound connections are strictly restricted to internal Domain Controllers, enterprise PKI, and management jump hosts.
* Background services attempting outbound connections to consumer cloud endpoints trigger continuous firewall denials, generate unnecessary network noise, and complicate operational monitoring.

### 3. Absolute Least Functionality on Tier 0 Assets
* Administration of Active Directory Domain Services, Group Policy, and Tier 0 identity infrastructure has zero dependency on game state synchronization.
* Disabling `XblGameSave` permanently terminates the background synchronization threads, file watchers, and registry hooks associated with consumer gaming.

### 4. MITRE ATT&CK Mapping
* **T1567 - Exfiltration Over Web Service**: Preventing unauthorized file synchronization channels to external consumer cloud storage.
* **T1071.001 - Application Layer Protocol: Web Protocols**: Enforcing strict outbound web traffic restrictions on administrative workstations.

---

## Legacy Impact & Compatibility
* **Administrative Operations**: Disabling `XblGameSave` is completely transparent to all Tier 0 management tasks, including RSAT, PowerShell Remoting, Active Directory Administrative Center, GPMC, and administrative backup scripts.
* **Compatibility Exception**: There are zero legitimate enterprise or administrative dependencies on Xbox Live game save services on Privileged Access Workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Game Save` (`XblGameSave`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawXblGameSave.ps1](../implementation_scripts/Configure-DisablePawXblGameSave.ps1)

```powershell
# Configure-DisablePawXblGameSave.ps1
# Description: Disables the unnecessary Xbox Live Game Save (XblGameSave) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Xbox Live Game Save service on PAW..." -ForegroundColor Cyan

$ServiceName = "XblGameSave"
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

[Download Script: Get-PawXblGameSaveStatus.ps1](../audit_scripts/Get-PawXblGameSaveStatus.ps1)

```powershell
# Get-PawXblGameSaveStatus.ps1
# Description: Audits the startup configuration of Xbox Live Game Save (XblGameSave) service on the local PAW system.

Write-Host "--- Auditing Xbox Live Game Save (XblGameSave) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "XblGameSave"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.46 (XblGameSave)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
