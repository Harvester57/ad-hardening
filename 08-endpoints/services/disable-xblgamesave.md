# [REQ-END-055] Disable Xbox Live Game Save Service (XblGameSave)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-055](../../07-paws/services/disable-xblgamesave.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The Xbox Live Game Save Service (`XblGameSave`, hosted in `svchost.exe` via `XblGameSave.dll`) manages background synchronization of game state, telemetry, and save container files between the local workstation file system and Microsoft Xbox Live consumer cloud storage.

### 1. Unsanctioned Cloud Synchronization and Data Exfiltration Risks
In an enterprise Active Directory environment, data synchronization to external cloud storage must be governed by corporate Data Loss Prevention (DLP) and Cloud Access Security Broker (CASB) policies:
* **Covert File Synchronization Channel**: `XblGameSave` maintains background file watchers over local AppData directories (`%LOCALAPPDATA%\Packages\...\SystemAppData\wgs`) and periodically uploads modified container files to consumer Microsoft cloud endpoints over HTTPS.
* **Potential for Data Staging and Exfiltration**: Attackers or unauthorized scripts operating in user space can potentially leverage unmonitored consumer synchronization mechanisms to stage files or synchronize unauthorized payloads, evading enterprise endpoint controls that inspect standard corporate egress channels.

### 2. Resource Overhead and Inefficient Workstation Operations
* The service runs background polling threads, monitors directory change notifications, and executes file verification routines.
* On enterprise endpoints, running background synchronization for consumer gaming assets consumes CPU cycles, memory, disk I/O, and corporate network bandwidth without delivering any business value.

### 3. Least Functionality in Corporate Workstations
* Disabling consumer game synchronization services aligns with the principle of least functionality (NIST SP 800-53 CM-7) and DISA STIG requirements for enterprise workstation minimization.
* Disabling `XblGameSave` ensures that unmonitored consumer cloud file transfers cannot take place.

### 4. MITRE ATT&CK Mapping
* **T1567 - Exfiltration Over Web Service**: Preventing the misuse of consumer cloud synchronization protocols for unauthorized external file transfer.
* **T1071.001 - Application Layer Protocol: Web Protocols**: Eliminating unauthorized background HTTPS communication channels to consumer cloud endpoints.

---

## Legacy Impact & Compatibility
* **Enterprise Operations**: Disabling `XblGameSave` is completely transparent to Active Directory operations, enterprise applications, OneDrive for Business, SharePoint synchronization, and approved backup software.
* **Consumer Gaming Applications**: Games installed via the Microsoft Store that depend on Xbox Live cloud save synchronization will be unable to upload or download cloud saves, restricting progress strictly to local save files if supported by the game.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Xbox Live Game Save` (`XblGameSave`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableXblGameSave.ps1](../implementation_scripts/Configure-DisableXblGameSave.ps1)

```powershell
# Configure-DisableXblGameSave.ps1
# Description: Disables the unnecessary Xbox Live Game Save (XblGameSave) service.

Write-Host "Applying hardening requirement: Disable Xbox Live Game Save service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-XblGameSaveStatus.ps1](../audit_scripts/Get-XblGameSaveStatus.ps1)

```powershell
# Get-XblGameSaveStatus.ps1
# Description: Audits the startup configuration of Xbox Live Game Save (XblGameSave) service.

Write-Host "--- Auditing Xbox Live Game Save (XblGameSave) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
