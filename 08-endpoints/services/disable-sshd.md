# [REQ-END-042] Disable OpenSSH SSH Server Service (sshd)

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-042](../../07-paws/services/disable-sshd.md)).*
* **Operating Systems**: Windows 10 (all supported editions), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

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
The OpenSSH SSH Server service (`sshd`) provides inbound secure shell access, interactive command-line terminal hosting (cmd/PowerShell), and secure file transfer (SFTP/SCP) over TCP port 22.

### 1. Inbound Network Listener and Lateral Movement Risks
While OpenSSH utilizes robust cryptographic transport algorithms, running an inbound SSH daemon on standard enterprise workstations introduces significant threat vectors:
* **Persistent Inbound Shell Listener**: Enabling `sshd` opens a listening socket on TCP port 22. On client endpoints, listening services invert the standard client-server security paradigm, turning workstations into accessible target servers susceptible to network discovery, automated password spraying, and brute-force credential stuffing (MITRE ATT&CK T1110).
* **SSH Tunneling and Reverse SOCKS Proxies**: Adversaries who gain access to an SSH account or implant SSH keys frequently abuse SSH port forwarding (`ssh -R` reverse tunneling, `ssh -D` dynamic SOCKS proxying) to route unauthorized traffic into corporate networks, bypass perimeter firewalls, and establish covert command-and-control channels (T1572 - Protocol Tunneling, T1090 - Proxy).
* **Bypassing Centralized Management and Auditing**: Unlike Windows PowerShell Remoting (WinRM/WSMAN), which integrates natively with Windows Event Forwarding, Script Block Logging (EID 4104), and Active Directory Group Policy controls, SSH interactive sessions may execute outside enterprise management frameworks unless dedicated SSH auditing infrastructure is maintained.

### 2. Client versus Server Operational Demarcation
Workstations and standard member servers function as administrative origins and clients, not remote service targets:
* Standard users and administrators initiate outbound administrative sessions (using the OpenSSH client `ssh.exe` or WinRM) toward designated jump boxes, bastion hosts, or managed Linux servers.
* Disabling the inbound `sshd` daemon enforces the principle of least functionality, eliminates TCP port 22 listeners across the workstation fleet, and prevents endpoints from serving as staging nodes for adversary lateral movement.

### 3. MITRE ATT&CK Mapping
* **T1021.004 - Remote Services: SSH**: Adversaries use SSH daemons for interactive lateral movement across internal systems.
* **T1572 - Protocol Tunneling**: Abusing SSH local and remote port forwarding to tunnel unauthorized traffic across enterprise firewalls.
* **T1110 - Brute Force**: Automated brute-force credential spraying against listening SSH daemons.

---

## Legacy Impact & Compatibility
* **OpenSSH Client Functionality**: Disabling the `sshd` server service does **not** impact the OpenSSH client (`ssh.exe`, `scp.exe`, `sftp.exe`). Administrators and developers can continue initiating outbound SSH connections to authorized servers and git repositories.
* **Windows Remote Management**: Enterprise remote management and automation via WinRM, PowerShell Remoting, WMI, and Remote Desktop (RDP) operate independently and are unaffected.
* **Developer Workstations**: If specific software engineers require inbound SSH for local debugging or container toolchains, implement an exception via an Organizational Unit (OU) policy with host-based firewall restrictions, while keeping `sshd` disabled by default across all general endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the target endpoints GPO (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\System Services`
4. Locate `OpenSSH SSH Server` (`sshd`), double-click to define the policy, and select **Disabled**.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-Disablesshd.ps1](../implementation_scripts/Configure-Disablesshd.ps1)

```powershell
# Configure-Disablesshd.ps1
# Description: Disables the unnecessary OpenSSH SSH Server (sshd) service.

Write-Host "Applying hardening requirement: Disable OpenSSH SSH Server service..." -ForegroundColor Cyan

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

*To verify the startup type of this unnecessary service:*

[Download Script: Get-sshdStatus.ps1](../audit_scripts/Get-sshdStatus.ps1)

```powershell
# Get-sshdStatus.ps1
# Description: Audits the startup configuration of OpenSSH SSH Server (sshd) service.

Write-Host "--- Auditing OpenSSH SSH Server (sshd) Service ---" -ForegroundColor Cyan

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
* **ANSSI Active Directory Hardening Guide**: Recommendations on host service minimization
* **DoD Windows 11 Computer STIG v2r6**: Unnecessary services restrictions
