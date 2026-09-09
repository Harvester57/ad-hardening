# [REQ-PAW-168] Administrative Templates: Disable SMBv1 Protocol Components for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration. *(For Tier 2 Client Workstations and Member Servers, refer to baseline [REQ-END-179](../../08-endpoints/admin-templates/configure-end-at-smbv1.md); for Domain Controllers, refer to [REQ-DC-016](../../02-domain-controllers/disable-smbv1.md)).*
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) serve as the sensitive administrative bridge between Tier 0 operators and Tier 0 Active Directory Domain Controllers. Any security compromise of a PAW results in complete loss of forest integrity. Legacy Server Message Block version 1 (SMBv1) introduces catastrophic architectural vulnerabilities that cannot be permitted on privileged hardware.

### 1. Threat Vectors and Architectural Insecurity
SMBv1 contains severe design flaws dating to early LAN protocols:
* **Remote Kernel Execution and Worm Propagation**: SMBv1 vulnerabilities (such as MS17-010 / CVE-2017-0144) allow unauthenticated remote attackers to execute arbitrary shellcode directly inside Windows kernel ring 0. On a PAW, this completely bypasses virtualization-based security (VBS), Credential Guard, and Endpoint Detection and Response (EDR) agents.
* **Absence of Cryptographic Integrity and Signing**: SMBv1 relies on legacy single-DES derived signatures and lacks pre-authentication integrity. An adversary situated on the management VLAN could perform adversary-in-the-middle (AiTM) packet manipulation or session hijacking during administrative file transfer operations.
* **Inability to Negotiate Secure Dialects**: Disabling the client driver (`mrxsmb10.sys`) guarantees that the PAW operating system kernel cannot be coerced into negotiating legacy dialects with rogue servers attempting NTLM credential harvesting or SMB downgrade relay attacks.

### 2. Privileged Access Environment Requirements
Tier 0 PAWs must never participate in peer-to-peer file sharing or connect to unmanaged legacy file shares. Administrative tooling, scripts, and updates must be delivered exclusively through authenticated, encrypted conduits (SMB 3.1.1 with AES-256-GCM signing/encryption, WinRM over HTTPS, or dedicated enterprise repositories). Completely disabling both the client driver and the server listener guarantees zero residual SMBv1 exposure.

### 3. MITRE ATT&CK Mapping
* **T1210 - Exploitation of Remote Services**: Lateral exploitation of legacy SMB vulnerabilities against administrative nodes.
* **T1557.001 - Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay**: Relaying captured administrative SMB authentications.
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**: Accessing administrative shares over unhardened network protocols.

---

## Legacy Impact & Compatibility
* **Operational Impact**: PAWs will be unable to access file shares hosted on legacy NAS appliances, obsolete embedded devices, or Windows Server 2003/XP hosts. Because Tier 0 management boundaries strictly forbid interaction with legacy non-Tier-0 systems, this constraint reinforces architectural isolation.
* **Administrative Workflows**: Tier 0 administrators must manage modern Domain Controllers and directory servers that fully support SMB 3.1.1 with mutual Kerberos authentication and AES encryption. No legitimate administrative tasks require SMBv1.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Configure the following policies:

* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Workstation`
  * **Configure SMB v1 client driver**: Set to `Enabled`
  * Set **Driver state** drop-down to: `Disable driver (recommended)`
* Navigate to: `Computer Configuration\Policies\Administrative Templates\Network\Lanman Server`
  * **Configure SMB v1 server**: Set to `Disabled`

4. Link the GPO to the PAW Organizational Unit and enforce policy replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtSmbv1.ps1](../implementation_scripts/Configure-PawAtSmbv1.ps1)

```powershell
#Configure-PawAtSmbv1.ps1
# Description: Configures Administrative Templates: Disable SMBv1 Protocol Components for PAWs.

Write-Host "Configuring Administrative Templates: Disable SMBv1 Protocol Components for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord -Force

if (-not (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters")) {
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable SMBv1 Protocol Components for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtSmbv1Status.ps1](../audit_scripts/Get-PawAtSmbv1Status.ps1)

```powershell
#Get-PawAtSmbv1Status.ps1
# Description: Audits Administrative Templates: Disable SMBv1 Protocol Components for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable SMBv1 Protocol Components for PAWs ---" -ForegroundColor Cyan
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
* **Microsoft Privileged Access Workstation Guidance**: PAW Hardware and Baseline Hardening Specifications
