# [REQ-PAW-042] Disable OpenSSH SSH Server Service for PAWs (sshd)

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For standard client workstations and member servers, refer to baseline [REQ-END-042](../../08-endpoints/services/disable-sshd.md)).*
* **Operating Systems**: Windows 10 Enterprise (all supported builds) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\System Services\OpenSSH SSH Server` -> **Disabled**
  * **Registry Path**: `HKLM\SYSTEM\CurrentControlSet\Services\sshd`
  * **Value Name**: `Start`
  * **Value Type**: `REG_DWORD`
  * **Value Data**: `4` (Disabled)

---

## Rationale
The OpenSSH SSH Server service (`sshd`) provides inbound secure shell access, remote command-line session hosting, and secure file transfer (SFTP/SCP) over TCP port 22.

### 1. Attack Vectors and Inbound Listening Risks on Administrative Stations
Operating an inbound SSH daemon on a Privileged Access Workstation creates grave security vulnerabilities:
* **Persistent Inbound Shell Listener**: Enabling `sshd` opens a listening socket on TCP port 22. Inbound network listeners expose the PAW to active network probing, automated credential spraying, and brute-force attacks from lower-trust network segments.
* **Adversary Pivoting and Reverse Tunnels**: Attackers who obtain SSH credentials or install unauthorized authorized_keys files can establish reverse SSH tunnels (`ssh -R`) and dynamic SOCKS proxies. This allows adversaries to bypass firewall boundaries, route unauthorized traffic directly through the PAW, and establish covert persistence into Tier 0 management enclaves (MITRE ATT&CK T1572 - Protocol Tunneling).

### 2. PAW Clean Source and Directional Isolation Requirements
A fundamental architectural tenet of the Microsoft Privileged Access Workstation model is that **PAWs are strictly administrative origins, never destinations**:
* **Directional Traffic Enforcement**: Administrative workflows must flow exclusively **outbound** from the PAW toward managed Tier 0 targets (Domain Controllers, PKI/CA servers, Tier 0 hypervisors). Inbound remote administration to a PAW from another host violates Tier 0 containment.
* **Credential Protection**: If an adversary compromises a lower-tier workstation or network appliance and can connect inbound to a PAW via SSH, they could execute local privilege escalation exploits, dump LSASS process memory, and extract cached Tier 0 Domain Admin Kerberos tickets and NTLM hashes.
* **Elimination of Listening Sockets**: Disabling `sshd` guarantees that TCP port 22 remains closed, ensuring the PAW maintains zero listening administrative services accessible over the network.

### 3. MITRE ATT&CK Mapping
* **T1021.004 - Remote Services: SSH**: Adversaries utilize inbound SSH listeners to pivot laterally into administrative hosts.
* **T1572 - Protocol Tunneling**: Leveraging SSH reverse port forwarding to tunnel traffic across network boundaries.
* **T1110 - Brute Force**: Credential spraying and brute-forcing against listening SSH daemons.

---

## Legacy Impact & Compatibility
* **Outbound SSH Administration**: Disabling the server service does not restrict the OpenSSH client (`ssh.exe`). Tier 0 administrators can continue initiating outbound SSH connections to manage network switches, hardware security modules (HSMs), or appliance consoles.
* **Inbound Access Prohibition**: Inbound remote desktop or shell access to a PAW is strictly prohibited under enterprise Tier 0 hardening baselines. PAW configuration and management are performed locally or enforced via Active Directory Group Policy.
* **Remote Management Tools**: Native Windows management tools (RSAT, PowerShell Remoting, WMI) directed outward from the PAW operate normally.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `OpenSSH SSH Server` (`sshd`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-DisablePawsshd.ps1](../implementation_scripts/Configure-DisablePawsshd.ps1)

```powershell
# Configure-DisablePawsshd.ps1
# Description: Disables the unnecessary OpenSSH SSH Server (sshd) service on the local PAW.

Write-Host "Applying hardening requirement: Disable OpenSSH SSH Server service on PAW..." -ForegroundColor Cyan

$ServiceName = "sshd"
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

[Download Script: Get-PawsshdStatus.ps1](../audit_scripts/Get-PawsshdStatus.ps1)

```powershell
# Get-PawsshdStatus.ps1
# Description: Audits the startup configuration of OpenSSH SSH Server (sshd) service on the local PAW system.

Write-Host "--- Auditing OpenSSH SSH Server (sshd) Service on PAW ---" -ForegroundColor Cyan

$ServiceName = "sshd"
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
* **CIS Microsoft Windows Client Benchmark**: Section 5.14 (sshd)
* **ANSSI Active Directory Hardening Guide**: Recommendations on limiting active background services on sensitive hosts
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
