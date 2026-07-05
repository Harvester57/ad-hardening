# [REQ-PAW-049] Disable Web Management Service Service for PAWs (WMSvc)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\WMSvc\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled. Disabling the Web Management Service (WMSvc) service directly supports this on Privileged Access Workstations:

1. IIS Web Management; unnecessary web console access daemon on endpoint systems.
2. On highly critical Tier 0 PAW systems, any running background service represents potential exploit surface. Restricting local capabilities to the absolute bare minimum is a primary security requirement.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Disabling this service is expected to be transparent for PAW administrative roles unless specific management software strictly relies on it.
* **Engineering Exception**: In the case of services like LxssManager (WSL), disabling is the expected secure baseline to prevent running unvetted Linux container namespaces on administrative workstations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Web Management Service` (`WMSvc`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawWMSvc.ps1](../implementation_scripts/Configure-DisablePawWMSvc.ps1)

```powershell
# Configure-DisablePawWMSvc.ps1
# Description: Disables the unnecessary Web Management Service (WMSvc) service on the local PAW.

Write-Host "Applying hardening requirement: Disable Web Management Service service on PAW..." -ForegroundColor Cyan

$ServiceName = "WMSvc"
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

[Download Script: Get-PawWMSvcStatus.ps1](../audit_scripts/Get-PawWMSvcStatus.ps1)

```powershell
# Get-PawWMSvcStatus.ps1
# Description: Audits the startup configuration of Web Management Service (WMSvc) service on the local PAW system.

Write-Host "--- Auditing Web Management Service (WMSvc) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "WMSvc"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.34 (WMSvc)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
