# [REQ-END-179] Administrative Templates: Disable SMBv1 Protocol Components

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-168](../../07-paws/admin-templates/configure-paw-at-smbv1.md); for Domain Controllers, refer to [REQ-DC-016](../../02-domain-controllers/disable-smbv1.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (all supported builds), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **Lanman Workstation (SMB Client Driver)**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation\Configure SMB v1 client driver` -> **Enabled** (Value: `Disable driver (recommended)`)
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10`
    * Value Name: `Start`
    * Value Type: `REG_DWORD`
    * Value Data: `4` (Disabled)
  * **Lanman Server (SMB Server Service)**:
    * GPO Path: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server\Configure SMB v1 server` -> **Disabled**
    * Registry Path: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
    * Value Name: `SMB1`
    * Value Type: `REG_DWORD`
    * Value Data: `0` (Disabled)

---

## Rationale
Server Message Block version 1 (SMBv1) is a legacy file and print sharing protocol designed in the early 1980s that suffers from severe architectural design flaws, obsolete cryptographic mechanisms, and extensive vulnerabilities exploited in widespread cyberattacks.

### 1. Architectural Insecurity and Exploitation Vectors
SMBv1 lacks modern integrity validation, message authentication, and transport layer encryption:
* **Remote Code Execution (RCE) and Wormable Exploits**: SMBv1 handling within the Windows kernel (`srv.sys` and `srvnet.sys`) was the primary execution vehicle for EternalBlue (MS17-010 / CVE-2017-0144), which facilitated devastating autonomous ransomware outbreaks including WannaCry, NotPetya, and BadRabbit. Buffer handling vulnerabilities in SMBv1 transaction processing allow unauthenticated remote attackers to execute arbitrary shellcode in ring 0 kernel space.
* **Lack of Pre-Authentication Integrity**: SMBv1 lacks pre-authentication integrity checks (introduced in SMB 3.1.1), making SMB sessions vulnerable to adversary-in-the-middle (AiTM) tampering, connection downgrades, and credential stripping.
* **Insecure Legacy Cryptography**: SMBv1 relies on DES and single-DES derived hashes for integrity signing, which can be cracked or forged in real time by adversaries, facilitating session hijacking and credential relaying.

### 2. Comprehensive Dual-Component Decommissioning
Effective deprecation of SMBv1 requires disabling both the client and server components:
* Setting `Start = 4` on the `mrxsmb10` service stops the SMBv1 client mini-redirector driver from loading into kernel memory, preventing the endpoint from initiating outbound SMBv1 connections to rogue or compromised servers.
* Setting `SMB1 = 0` under `LanmanServer\Parameters` prevents the local server service from negotiating SMBv1 sessions with inbound network nodes, closing the listening attack surface on TCP port 445 and NetBIOS port 139.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Exploitation of legacy SMBv1 vulnerabilities for network lateral movement.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Intercepting and relaying unauthenticated or weakly signed SMB negotiation handshakes.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Adversary access to administrative shares over insecure SMB channels.

---

## Legacy Impact & Compatibility
* **Enterprise Network Compatibility**: Modern Windows releases (Windows 10 version 1709+, Windows 11, Windows Server 2019+) disable SMBv1 by default. Commercial file servers running Windows Server 2012 and later, Samba 4.x, and contemporary NAS operating systems fully support SMB 2.0.2, 2.1, 3.0, 3.0.2, and 3.1.1.
* **Legacy Storage and Embedded Devices**: Network appliances manufactured prior to 2010 (e.g., legacy network scanners, multi-function copiers, obsolete Linux-based NAS units, or embedded industrial controllers) that only support SMBv1 will be unable to access file shares on hardened workstations or receive scan-to-folder transmissions.
* **Remediation for Legacy Dependencies**: Organizations must upgrade device firmware, replace obsolete hardware, or transition file ingest workflows to secure protocols (e.g., SFTP, HTTPS WebDAV, or cloud storage APIs) rather than enabling SMBv1 on corporate endpoints.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation`
  * **Configure SMB v1 client driver**: Set to `Enabled`
  * Set **Driver state** drop-down to: `Disable driver (recommended)`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server`
  * **Configure SMB v1 server**: Set to `Disabled`

4. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across endpoints using `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtSmbv1.ps1](../implementation_scripts/Configure-EndAtSmbv1.ps1)

```powershell
#Configure-EndAtSmbv1.ps1
# Description: Configures Administrative Templates: Disable SMBv1 Protocol Components.

Write-Host "Configuring Administrative Templates: Disable SMBv1 Protocol Components..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable SMBv1 Protocol Components applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtSmbv1Status.ps1](../audit_scripts/Get-EndAtSmbv1Status.ps1)

```powershell
#Get-EndAtSmbv1Status.ps1
# Description: Audits Administrative Templates: Disable SMBv1 Protocol Components.

Write-Host "--- Auditing Administrative Templates: Disable SMBv1 Protocol Components ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
$ValueName = "Start"
$ExpectedValue = 4
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

$TargetKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$ValueName = "SMB1"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows 10 Enterprise Benchmark: Section 18.4.2, Section 18.4.3; CIS Microsoft Windows 11 Enterprise Benchmark: Section 18.4.2, Section 18.4.3
* **DISA STIG**: Windows 10 STIG Rule WN10-CC-000210, Windows 11 STIG Rule WN11-CC-000210
* **ANSSI Active Directory Hardening Guide**: Recommendation R42 (Decommissioning legacy network protocols and SMBv1)
* **Microsoft Security Baseline**: Windows Client and Server Security Baseline (Disabling SMBv1 Client and Server)
* **Microsoft Security Bulletin**: MS17-010 (Vulnerabilities in Microsoft Windows SMB Server - CVE-2017-0143, CVE-2017-0144)
