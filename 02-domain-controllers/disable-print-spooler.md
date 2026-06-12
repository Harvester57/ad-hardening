# Hardening Requirement: Disable Print Spooler Service

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Service**: `Print Spooler`
  * **Setting**: `Define this policy setting: Disabled`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\Spooler` -> `Start` = `4` (REG_DWORD)

---

## Rationale
The Windows Print Spooler service (`Spooler`) is enabled and running by default on Windows Server installations, including Domain Controllers. However, Domain Controllers do not print and should never act as print servers.

The Print Spooler service has a history of high-severity vulnerabilities, including remote code execution exploits (e.g., the PrintNightmare vulnerability family - CVE-2021-1675 / CVE-2021-34527). Additionally, the service is exploited in coercion attacks such as the PetitPotam technique or printer-based authentication coercion. An attacker with low-privilege network access can send an RPC request to the DC's Print Spooler service (specifically utilizing APIs such as `RpcRemoteFindFirstPrinterChangeNotificationEx`), forcing the Domain Controller to authenticate to a malicious listener over NTLM. The attacker can then relay this authentication to take over the Active Directory domain. Disabling the service completely closes these high-risk vectors.

---

## Legacy Impact & Compatibility
* **No Functional Impact**: Disabling the Print Spooler service on a Domain Controller has no negative impact on Active Directory replication, client logins, DNS, or directory services.
* **Pruning Shared Printers**: If the Domain Controller was historically used to host shared printers (which violates security best practices), those print queues will become unavailable and must be migrated to dedicated Member Servers.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the GPO linked to the Domain Controllers Organizational Unit (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Find the **Print Spooler** service in the list and double-click it.
5. Check **Define this policy setting** and select **Disabled**.
6. Link the GPO to the Domain Controllers OU.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally.

[Download Script: Configure-DisablePrintSpooler.ps1](implementation_scripts/Configure-DisablePrintSpooler.ps1)

```powershell
# Configure-DisablePrintSpooler.ps1
# Description: Stops and disables the Print Spooler service.

Write-Host "Applying hardening requirement: Disable Print Spooler..." -ForegroundColor Cyan

$serviceName = "Spooler"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    if ($service.Status -eq "Running") {
        Write-Host "Stopping service $($serviceName)..." -ForegroundColor Gray
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    }
    
    # Configure startup type to disabled
    Set-Service -Name $serviceName -StartupType Disabled
    Write-Host "Service $($serviceName) has been stopped and disabled." -ForegroundColor Green
} else {
    Write-Host "Service $($serviceName) not found." -ForegroundColor Yellow
}
```

*To verify the setting has been applied:*
[Download Script: Get-PrintSpoolerStatus.ps1](audit_scripts/Get-PrintSpoolerStatus.ps1)

```powershell
# Get-PrintSpoolerStatus.ps1
# Description: Audits the operational status and startup type of the Print Spooler service.

Write-Host "--- Auditing Print Spooler Service ---" -ForegroundColor Cyan

$serviceName = "Spooler"
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

if ($service) {
    $status = $service.Status
    $startType = $service.StartType
    
    if ($status -eq "Stopped" -and $startType -eq "Disabled") {
        Write-Host "[+] Print Spooler is secure (Stopped and Disabled)." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: Print Spooler service status is $($status) and StartType is $($startType) (Required: Stopped & Disabled)." -ForegroundColor Red
    }
} else {
    Write-Host "[+] Print Spooler service is not installed on this system (Secure)." -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R4 (Minimization of service execution and software installation)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 2.2.33 (Ensure 'Print Spooler' is set to 'Disabled')
* **Microsoft Security Guidance**: Recommendations for disabling Print Spooler on Domain Controllers
* **Other Reference**: CVE-2021-1675 / CVE-2021-34527 (PrintNightmare mitigation guidance)
