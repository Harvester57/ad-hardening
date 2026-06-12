# Hardening Requirement: Configure AppLocker Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**: Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker

---

## Rationale
Privileged Access Workstations (PAWs) host highly sensitive Tier 0 credentials. If administrative workstations are allowed to execute arbitrary binaries, scripts, or installation packages, they become highly susceptible to malware infections, remote access trojans, and credential harvesting tools (like Mimikatz).

Enforcing strict execution controls via AppLocker ensures that:
1. **Execution Control**: Only signed operating system files, approved software binaries, and scripts are allowed to execute.
2. **Standard User Restrictions**: Any standard users or unauthorized accounts cannot run executable files or installers from writeable directories (like `%TEMP%` or `%USERPROFILE%`).
3. **Defense-in-Depth**: Even if an administrator is tricked into downloading a malicious file, AppLocker blocks the execution of the binary, preventing the compromise of the endpoint.

---

## Legacy Impact & Compatibility
* **Authorized Software Only**: Only administrative tools, management consoles, and approved software can be run on the PAW. Users will be unable to run portable utilities or install unapproved tools.
* **AppLocker Service Requirement**: The Application Identity service (`AppIDSvc`) must be configured to start automatically and run continuously to enforce AppLocker policies. If the service is stopped, rules are not enforced.
* **Administrative Overhead**: Creating and maintaining AppLocker rules requires cataloging administrative tool requirements and updating rules when new utilities are introduced.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit the GPO linked to the PAWs Organizational Unit (OU) (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Application Control Policies\AppLocker`
4. Right-click **Executable Rules** and select **Create Default Rules** (this permits Windows files and program files).
5. Delete the default rule allowing "Everyone" to run files in all locations, and replace it with a rule allowing only authorized administrative groups (e.g., `Tier0-Admins`) to run binaries outside the default system locations.
6. Set AppLocker Enforcement:
   * Right-click **AppLocker** and select **Properties**.
   * On the **Enforcement** tab, check **Configured** under **Executable rules** and select **Enforce rules**.
7. Link the GPO to the PAWs Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure the Application Identity service (`AppIDSvc`) locally to ensure that AppLocker policies are actively enforced on the endpoint.

[Download Script: Configure-PawAppLockerService.ps1](implementation_scripts/Configure-PawAppLockerService.ps1)

```powershell
# Configure-PawAppLockerService.ps1
# Description: Configures the Application Identity service (AppIDSvc) to start automatically and run.

Write-Host "Applying AppLocker Identity service hardening..." -ForegroundColor Cyan

$AppLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($AppLockerService) {
    Set-Service -Name AppIDSvc -StartupType Automatic
    Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    Write-Host "[+] Application Identity Service (AppIDSvc) set to Automatic and started." -ForegroundColor Green
} else {
    Write-Warning "[-] Application Identity Service not found on this machine."
}
```

*To verify the AppLocker service status:*

[Download Script: Test-PawAppLockerStatus.ps1](audit_scripts/Test-PawAppLockerStatus.ps1)

```powershell
# Test-PawAppLockerStatus.ps1
# Description: Checks the current configuration and operational status of the Application Identity service.

Write-Host "--- Auditing AppLocker Service Status ---" -ForegroundColor Cyan

$AppIDSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue

if ($AppIDSvc) {
    if ($AppIDSvc.Status -eq "Running" -and $AppIDSvc.StartType -eq "Automatic") {
        Write-Host "    - AppLocker Service Status: Running | Startup: Automatic (Secure)" -ForegroundColor Green
    } else {
        Write-Host "    - VULNERABLE: AppLocker Service Status: $($AppIDSvc.Status) | Startup: $($AppIDSvc.StartType) (Should be Running/Automatic)" -ForegroundColor Red
    }
} else {
    Write-Host "    - VULNERABLE: Application Identity Service (AppIDSvc) is not installed." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R58 (Use of Privileged Access Workstations)
* **CIS Microsoft Windows 10/11 Benchmark**: Section 18.9 (AppLocker Application Control)
* **Microsoft Security Baselines**: AppLocker deployment guidance for high-security environments.
