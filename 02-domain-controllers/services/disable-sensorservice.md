# [REQ-DC-057] Disable Sensor Service on Domain Controllers (SensorService)

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs) running Windows Server.
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Preferences\Windows Settings\Registry`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\SensorService\Start`

---

## Rationale
Domain Controllers represent the highest privilege tier (Tier 0) in the Active Directory forest. Minimizing the execution footprint on these critical servers is an essential hardening guideline. Disabling the Sensor Service (SensorService) service directly supports this:

1. Core sensor service; irrelevant to servers.
2. Reducing running background services closes potential vectors for local privilege escalation and memory space exploits on the directory controllers.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Disabling this service has no impact on core Active Directory Domain Services (AD DS), Kerberos, DNS, or SYSVOL replication functionality.
* **Special Hardware/Configurations**: Smart card services or time sync should remain enabled if strictly required, but the services listed in the baseline can be safely disabled on standard directory servers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Because these services are not managed through standard GPO Administrative Templates, configure Group Policy Preferences (GPP) for the registry:

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain management host.
2. Edit the GPO linked to your Domain Controllers Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a new Registry Preference (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\SensorService`
   * **Value name**: `Start`
   * **Value type**: `REG_DWORD`
   * **Value data**: `4`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableSensorService.ps1](../implementation_scripts/Configure-DisableSensorService.ps1)

```powershell
# Configure-DisableSensorService.ps1
# Description: Disables the unnecessary Sensor Service (SensorService) service on Domain Controllers.

Write-Host "Applying hardening requirement: Disable Sensor Service service on Domain Controllers..." -ForegroundColor Cyan

$ServiceName = "SensorService"
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

*To verify the startup type of this unnecessary service on the Domain Controller:*

[Download Script: Get-SensorServiceStatus.ps1](../audit_scripts/Get-SensorServiceStatus.ps1)

```powershell
# Get-SensorServiceStatus.ps1
# Description: Audits the registry startup state of unnecessary Sensor Service (SensorService) service.

Write-Host "--- Auditing Sensor Service (SensorService) Service on Domain Controller ---" -ForegroundColor Cyan

$ServiceName = "SensorService"
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
* **Microsoft Windows Server Security Guidance**: Guidelines for disabling system services in Windows Server
* **ANSSI AD Hardening Guide**: Recommendation R4 (Minimization of service execution)
* **CIS Microsoft Windows Server Benchmark**: Service minimization baselines
