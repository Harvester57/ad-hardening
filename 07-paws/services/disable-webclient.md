# [REQ-PAW-166] Disable WebClient Service for PAWs (WebClient)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
  * **Registry Location**: `HKLM\SYSTEM\CurrentControlSet\Services\WebClient\Start`

---

## Rationale
To minimize the attack surface of Privileged Access Workstations (PAWs), all unnecessary background system services must be stopped and disabled.

Disabling the WebClient service on Tier 0 PAWs provides critical security benefits:
1. **Eliminating WebDAV Credential Coercion**: The WebClient service handles Web Distributed Authoring and Versioning (WebDAV) file requests over HTTP/HTTPS. Attackers can trigger WebDAV coercion methods (e.g., via malicious file explorer shortcuts, UNC links, or RPC coercion) that force the administrative host to transmit NTLM authentication to an attacker-controlled HTTP server. Because HTTP authentication does not enforce SMB signing, these credentials can be relayed to critical Active Directory services.
2. **Tier 0 Principle of Least Functionality**: PAW workstations are dedicated strictly to directory and infrastructure administration. They must never mount or interact with remote WebDAV shares.

---

## Legacy Impact & Compatibility
* **Normal Operations**: Disabling this service is completely transparent for PAW administrative roles unless third-party administrative tooling specifically relies on WebDAV transport (which is prohibited under Tier 0 standards).
* **WebDAV Mapping Blocked**: Users will not be able to map WebDAV shares in Windows Explorer.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `WebClient`, double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawWebClient.ps1](../implementation_scripts/Configure-DisablePawWebClient.ps1)

```powershell
# Configure-DisablePawWebClient.ps1
# Description: Disables the unnecessary WebClient service on the local PAW system.

Write-Host "Applying hardening requirement: Disable WebClient service on PAW..." -ForegroundColor Cyan

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

*To verify the startup configuration of the WebClient service on the PAW:*

[Download Script: Get-PawWebClientStatus.ps1](../audit_scripts/Get-PawWebClientStatus.ps1)

```powershell
# Get-PawWebClientStatus.ps1
# Description: Audits the startup configuration of the WebClient service on the local PAW system.

Write-Host "--- Auditing WebClient Service on PAW ---" -ForegroundColor Cyan

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
* **CIS Microsoft Windows Client Benchmark**: System service minimization guidelines
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on administrative systems
* **DoD Windows 11 Computer STIG**: Unnecessary system services restrictions
