# [REQ-DC-001] Disable SMBv1

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Disable SMBv1 Server**:
    * Path: `Computer Configuration\Preferences\Windows Settings\Registry`
    * Key Path: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
    * Value Name: `SMB1`
    * Value Type: `REG_DWORD`
    * Value Data: `0`
  * **Disable SMBv1 Client**:
    * Path: `Computer Configuration\Preferences\Windows Settings\Registry`
    * Key Path: `SYSTEM\CurrentControlSet\Services\mrxsmb10`
    * Value Name: `Start`
    * Value Type: `REG_DWORD`
    * Value Data: `4`

---

## Rationale
SMBv1 (Server Message Block version 1) is a legacy networking protocol designed over 30 years ago. It lacks modern security features such as packet encryption, cryptographic signing enforcement, and robust integrity verification. 

SMBv1 contains severe remote code execution (RCE) vulnerabilities (e.g., the EternalBlue vulnerability mitigated in MS17-010). Attackers can exploit SMBv1 to execute commands remotely, capture credentials, or perform lateral movement across the domain network. Domain Controllers (Tier 0) are highly sensitive targets, and keeping SMBv1 enabled presents an unacceptable risk. Disabling both the server protocol and the client driver eliminates this entire attack surface.

---

## Legacy Impact & Compatibility
* **Authentication Failures**: Disabling SMBv1 breaks network sharing and file transfer with outdated systems, including Windows XP, Windows Server 2003, early Linux distributions using old Samba versions, older network-attached storage (NAS) appliances, and legacy printers or scanners.
* **Pre-requisite Audit**: In legacy environments, network administrators should audit SMBv1 usage using Windows Event Logs (Microsoft-Windows-SMBServer/Analytic log) before disabling the protocol. If legacy clients exist, they must be upgraded or isolated.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

Configure Group Policy Preferences to enforce the registry settings:

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
4. Create a new Registry Preference to disable the SMBv1 Server (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
   * **Value name**: `SMB1`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0`
5. Create a second Registry Preference to disable the SMBv1 Client Driver (Right-click **Registry -> New -> Registry Item**):
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\mrxsmb10`
   * **Value name**: `Start`
   * **Value type**: `REG_DWORD`
   * **Value data**: `4`
6. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: Configure-DisableSMBv1.ps1](implementation_scripts/Configure-DisableSMBv1.ps1)

```powershell
# Configure-DisableSMBv1.ps1
# Description: Disables SMBv1 server protocol and mrxsmb10 client driver.

Write-Host "Applying hardening requirement: Disable SMBv1..." -ForegroundColor Cyan

# 1. Disable SMBv1 Server
$srvRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $srvRegPath)) {
    New-Item -Path $srvRegPath -Force | Out-Null
}
Set-ItemProperty -Path $srvRegPath -Name "SMB1" -Value 0 -Type DWord
Write-Host "SMBv1 Server registry configuration applied." -ForegroundColor Green

# Use standard cmdlet if available
if (Get-Command -Name Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "SMBv1 Server protocol disabled via cmdlet." -ForegroundColor Green
}

# 2. Disable SMBv1 Client Driver
$clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
if (Test-Path $clientRegPath) {
    Set-ItemProperty -Path $clientRegPath -Name "Start" -Value 4 -Type DWord
    Write-Host "SMBv1 Client mrxsmb10 driver disabled." -ForegroundColor Green
} else {
    Write-Host "mrxsmb10 driver registry key not found (may already be removed)." -ForegroundColor Yellow
}

Write-Host "Hardening applied successfully. A system reboot is required." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-SMBv1Status.ps1](audit_scripts/Get-SMBv1Status.ps1)

```powershell
# Get-SMBv1Status.ps1
# Description: Audits the registry configuration of SMBv1 server and client components.

Write-Host "--- Auditing SMBv1 Configuration ---" -ForegroundColor Cyan
$vulnerable = $false

# Check Server configuration
if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    $smbConfig = Get-SmbServerConfiguration
    if ($smbConfig.EnableSMB1Protocol -eq $true) {
        Write-Host "[!] VULNERABLE: SMBv1 Server protocol is enabled via configuration." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] SMBv1 Server protocol is disabled." -ForegroundColor Green
    }
} else {
    $srvReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ErrorAction SilentlyContinue
    if ($srvReg -and $srvReg.SMB1 -eq 1) {
        Write-Host "[!] VULNERABLE: SMB1 registry parameter is set to 1 (Enabled)." -ForegroundColor Red
        $vulnerable = $true
    } else {
        Write-Host "[+] SMB1 registry parameter is disabled or not present." -ForegroundColor Green
    }
}

# Check Client configuration
$driverReg = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -ErrorAction SilentlyContinue
if ($driverReg -and $driverReg.Start -ne 4) {
    Write-Host "[!] VULNERABLE: mrxsmb10 client driver is not disabled (Start value: $($driverReg.Start))." -ForegroundColor Red
    $vulnerable = $true
} else {
    Write-Host "[+] mrxsmb10 client driver is disabled." -ForegroundColor Green
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Section 18.9.72 (Ensure 'Configure SMBv1 client driver' is set to 'Enabled: Disable driver')
* **Microsoft Security Baseline**: Domain Controller / Member Server Baseline configurations
