# Hardening Requirement: Enforce SMBv3 Security and Digitally Sign/Encrypt Communications

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, PAWs, Tier 2 Client Workstations.
* **Operating Systems**: Windows Server 2016 (and above), Windows 10 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Signing Policies**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
    * Microsoft network client: Digitally sign communications (always)
    * Microsoft network client: Digitally sign communications (if server agrees)
    * Microsoft network server: Digitally sign communications (always)
    * Microsoft network server: Digitally sign communications (if client agrees)
  * **Dialect Policies**: `Computer Configuration\Administrative Templates\Network\Lanman Server` and `Lanman Workstation` -> **Mandate the minimum version of SMB**
  * **Registry Locations**:
    * `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
    * `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`

---

## Rationale
Server Message Block (SMB) version 1.0 (SMBv1) is obsolete, highly insecure, and vulnerable to critical exploits (such as MS17-010 / EternalBlue, which enabled the global spread of WannaCry and NotPetya). SMBv2, while newer, lacks modern cryptographic protection and is prone to Man-in-the-Middle (MitM) interception and NTLM relaying.

Enforcing SMBv3 (minimum version 3.0.0 or 3.1.1) provides significant security advantages:
1. **AES-GCM Encryption**: Protects data in transit from passive sniffing and tampering. Enforcing encryption is critical on Domain Controllers (specifically for Sysvol and Netlogon shares) and servers hosting sensitive business files.
2. **Pre-Authentication Integrity**: Prevents tampering with SMB negotiation packets (mitigating downgrade attacks).
3. **SMB Signing**: Adds a cryptographic signature to all packets. Mandating SMB signing (specifically `Digitally sign communications (always)`) protects against SMB Relay attacks, where an attacker intercepts a NTLM authentication hash on the local network and replays it to a target server to gain unauthorized access.

---

## Legacy Impact & Compatibility
* **Legacy Systems**: Any client or server operating system that does not support SMB 3.x (such as Windows Server 2008, Windows Vista, or old versions of Linux/Samba) will fail to establish connections if SMBv3 is mandated or if SMB encryption is required.
* **Multifunction Printers and NAS**: Older network scanners, printers, and NAS storage appliances that only support SMBv1 or SMBv2 will no longer be able to write files to network shares. These devices must be updated or isolated to a dedicated segment with specialized access rules.
* **SYSVOL Replication**: For Domain Controllers, ensuring DFS Replication is migrated to DFSR (which supports SMBv3) is a prerequisite.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### 1. Configure SMB Signing Policies
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Create or edit a GPO targeting all domain assets (e.g., `GPO_Hardening_SMB_Security`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following four policies:
   * **Microsoft network client: Digitally sign communications (always)**: `Enabled`
   * **Microsoft network client: Digitally sign communications (if server agrees)**: `Enabled`
   * **Microsoft network server: Digitally sign communications (always)**: `Enabled`
   * **Microsoft network server: Digitally sign communications (if client agrees)**: `Enabled`

#### 2. Mandate Minimum SMB Dialects
On systems that support ADMX templates for SMB dialects (Windows 11 / Server 2022+):
1. Navigate to:
   `Computer Configuration\Administrative Templates\Network\Lanman Server`
2. Double-click **Mandate the minimum version of SMB**:
   * Set the policy to **Enabled**.
   * Set the minimum version to `SMB 3.0.0` (or `SMB 3.1.1` to require the latest dialect).
3. Navigate to:
   `Computer Configuration\Administrative Templates\Network\Lanman Workstation`
4. Double-click **Mandate the minimum version of SMB**:
   * Set the policy to **Enabled**.
   * Set the minimum version to `SMB 3.0.0` (or `SMB 3.1.1`).

#### 3. Disable SMBv1 Driver via GPO Preferences
To ensure the SMBv1 driver is disabled on older machines, deploy a registry change:
1. Navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry**, select **New** -> **Registry Item**:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
   * **Value name**: `SMB1`
   * **Value type**: `REG_DWORD`
   * **Value data**: `0`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following scripts locally to enforce SMBv3 standards.

#### Remediation Script:
[Download Script: Set-SMBSecurity.ps1](implementation_scripts/Set-SMBSecurity.ps1)

```powershell
# Set-SMBSecurity.ps1
# Description: Disables SMBv1, mandates signing, sets SMBv3 as minimum dialect, and enforces encryption.

Write-Host "Enforcing SMBv3 security settings..." -ForegroundColor Cyan

# 1. Disable SMBv1 Protocol globally (Server side)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false | Out-Null
Write-Host "SMBv1 server protocol disabled." -ForegroundColor Green

# 2. Disable SMBv1 Driver (Windows Optional Feature)
$SMB1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
if ($null -ne $SMB1Feature -and $SMB1Feature.State -eq "Enabled") {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue | Out-Null
    Write-Host "SMB1 optional feature disabled." -ForegroundColor Green
}

# 3. Configure SMB Signing & Encryption on Server
Set-SmbServerConfiguration -RequireSecuritySignature $true -EncryptData $true -Confirm:$false | Out-Null
Write-Host "SMB Server signing and encryption mandated." -ForegroundColor Green

# 4. Configure SMB Signing & Encryption on Client
Set-SmbClientConfiguration -RequireSecuritySignature $true -Confirm:$false | Out-Null
Write-Host "SMB Client signing mandated." -ForegroundColor Green

# 5. Enforce Minimum Dialects in Registry (Server and Client)
$ServerParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$ClientParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

# Write minimum dialect version 0x00000300 (SMB 3.0.0)
if (-not (Test-Path $ServerParamsPath)) {
    New-Item -Path $ServerParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $ServerParamsPath -Name "MinSMB2Dialect" -Value 0x00000300 -Type DWord -Force | Out-Null

if (-not (Test-Path $ClientParamsPath)) {
    New-Item -Path $ClientParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientParamsPath -Name "MinSMB2Dialect" -Value 0x00000300 -Type DWord -Force | Out-Null

# Disable legacy fallback protocols (e.g. NetBIOS over TCP/IP) if possible, but keep focus on SMBv3
Write-Host "SMBv3 minimum dialect rules configured." -ForegroundColor Green
```

#### Audit Script:
[Download Script: Test-SMBSecurity.ps1](audit_scripts/Test-SMBSecurity.ps1)

```powershell
# Test-SMBSecurity.ps1
# Description: Audits local SMB configuration for signing, encryption, and dialects.

Write-Host "Auditing SMB security configuration..." -ForegroundColor Cyan

$NonCompliantCount = 0

# Retrieve configurations
$ServerConfig = Get-SmbServerConfiguration
$ClientConfig = Get-SmbClientConfiguration

# 1. Audit SMBv1 Server status
if ($ServerConfig.EnableSMB1Protocol -eq $true) {
    Write-Host "    - SMBv1 Server protocol is enabled (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMBv1 Server protocol is disabled (Compliant)." -ForegroundColor Green
}

# 2. Audit Signing Requirements
if ($ServerConfig.RequireSecuritySignature -ne $true) {
    Write-Host "    - SMB Server signing is not required (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Server signing is mandated (Compliant)." -ForegroundColor Green
}

if ($ClientConfig.RequireSecuritySignature -ne $true) {
    Write-Host "    - SMB Client signing is not required (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Client signing is mandated (Compliant)." -ForegroundColor Green
}

# 3. Audit Encryption Requirements
if ($ServerConfig.EncryptData -ne $true) {
    Write-Host "    - SMB Server global data encryption is not enforced (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
} else {
    Write-Host "    - SMB Server global data encryption is enforced (Compliant)." -ForegroundColor Green
}

# 4. Audit Registry Dialects
$ServerParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$ClientParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

if (Test-Path $ServerParamsPath) {
    $ServerMinDialect = Get-ItemPropertyValue -Path $ServerParamsPath -Name "MinSMB2Dialect" -ErrorAction SilentlyContinue
    if ($null -eq $ServerMinDialect -or $ServerMinDialect -lt 0x00000300) {
        Write-Host "    - Server minimum dialect is less than SMB 3.0 or not set (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        Write-Host "    - Server minimum dialect is set to SMB 3.0+ (Compliant)." -ForegroundColor Green
    }
} else {
    Write-Host "    - LanmanServer registry path is missing (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if (Test-Path $ClientParamsPath) {
    $ClientMinDialect = Get-ItemPropertyValue -Path $ClientParamsPath -Name "MinSMB2Dialect" -ErrorAction SilentlyContinue
    if ($null -eq $ClientMinDialect -or $ClientMinDialect -lt 0x00000300) {
        Write-Host "    - Client minimum dialect is less than SMB 3.0 or not set (Non-Compliant)." -ForegroundColor Red
        $NonCompliantCount++
    } else {
        Write-Host "    - Client minimum dialect is set to SMB 3.0+ (Compliant)." -ForegroundColor Green
    }
} else {
    Write-Host "    - LanmanWorkstation registry path is missing (Non-Compliant)." -ForegroundColor Red
    $NonCompliantCount++
}

if ($NonCompliantCount -eq 0) {
    Write-Host "SMB Security configuration: Compliant." -ForegroundColor Green
} else {
    Write-Host "SMB Security configuration: Non-Compliant ($($NonCompliantCount) issue(s) detected)." -ForegroundColor Red
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R21 (Disabling SMBv1), Recommendation R22 (SMB signing and encryption)
* **CIS Windows Server 2016 Benchmark**: Section 2.3.10.1 (Microsoft network client: Digitally sign communications (always)) and Section 2.3.10.2 (Microsoft network server: Digitally sign communications (always))
* **Microsoft Security Guidance**: SMB security enhancements and dialect management
