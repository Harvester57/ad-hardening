# [REQ-END-039] Disable Internet Connection Sharing (ICS) Service (SharedAccess)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Start`

---

## Rationale
To minimize the attack surface of standard client endpoints and member servers, all unnecessary system services must be disabled. Disabling the Internet Connection Sharing (ICS) (SharedAccess) service directly supports this:

1. Provides NAT, addressing, and name resolution; represents security bridging risk.
2. By ensuring this service is disabled, we remove a potentially vulnerable network listener or local subsystem, decreasing both the remote and local exposure.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Disabling this service is expected to be transparent for standard Active Directory domain operations unless specific business functionality requires the service.
* **Verification**: Administrators must verify that client operations do not rely on local Internet Connection Sharing (ICS) capabilities before domain-wide enforcement.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `Internet Connection Sharing (ICS)` (`SharedAccess`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisableSharedAccess.ps1](../implementation_scripts/Configure-DisableSharedAccess.ps1)

```powershell
# Configure-DisableSharedAccess.ps1
# Description: Disables the unnecessary Internet Connection Sharing (ICS) (SharedAccess) service.

Write-Host "Applying hardening requirement: Disable Internet Connection Sharing (ICS) service..." -ForegroundColor Cyan

$ServiceName = "SharedAccess"
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

[Download Script: Get-SharedAccessStatus.ps1](../audit_scripts/Get-SharedAccessStatus.ps1)

```powershell
# Get-SharedAccessStatus.ps1
# Description: Audits the startup configuration of Internet Connection Sharing (ICS) (SharedAccess) service.

Write-Host "--- Auditing Internet Connection Sharing (ICS) (SharedAccess) Service ---" -ForegroundColor Cyan

$ServiceName = "SharedAccess"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.9 (SharedAccess)
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
