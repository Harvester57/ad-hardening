# [REQ-DC-009] Enforce SMB Message Signing

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Microsoft network server: Digitally sign communications (always)**:
    * Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
    * Policy: `Microsoft network server: Digitally sign communications (always)`
    * Setting: `Enabled`
    * Registry: `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters` -> `RequireSecuritySignature` = `1` (REG_DWORD)
  * **Microsoft network client: Digitally sign communications (always)**:
    * Path: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
    * Policy: `Microsoft network client: Digitally sign communications (always)`
    * Setting: `Enabled`
    * Registry: `HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters` -> `RequireSecuritySignature` = `1` (REG_DWORD)

---

## Rationale
Server Message Block (SMB) authentication is vulnerable to man-in-the-middle (MitM) and relay attacks. If SMB signing is not enforced, an attacker positioned on the local network can intercept SMB authentication sessions from client systems and relay them to another host (e.g., a Domain Controller or high-value member server). If the relayed user credential possesses administrative rights on the target host, the attacker can execute commands remotely (e.g., via PsExec/WMI) and compromise the system without knowing the password.

Enforcing SMB signing ensures that all SMB packets are digitally signed using session keys. This guarantees the authenticity of both the sender and the receiver and ensures packet integrity. If an attacker attempts to relay or modify the packets, the cryptographic signature check fails, and the session is terminated. Enforcing this on both server and client roles is a fundamental defense against lateral movement and domain takeover.

---

## Legacy Impact & Compatibility
* **Performance Overhead**: Enforcing SMB signing introduces a slight CPU processing overhead for signing and verifying packets. On modern hardware supporting instruction sets such as AES-NI, this performance impact is negligible.
* **Legacy Compatibility**: Legacy operating systems (e.g., Windows 98/NT4) or outdated third-party SMB client implementations that do not support SMB signing will be blocked from accessing SYSVOL, NETLOGON, or other file shares on Domain Controllers. Ensure all network systems support SMBv2 or higher with signing capabilities.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Policy**: `Microsoft network server: Digitally sign communications (always)`
     * **Setting**: `Enabled`
   * **Policy**: `Microsoft network client: Digitally sign communications (always)`
     * **Setting**: `Enabled`
5. Link the GPO to the appropriate Organizational Unit (OU) containing the target assets.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the settings locally.

[Download Script: Configure-SMBSigning.ps1](implementation_scripts/Configure-SMBSigning.ps1)

```powershell
# Configure-SMBSigning.ps1
# Description: Enforces SMB signing for both SMB server and client.

Write-Host "Applying hardening requirement: Enforce SMB Message Signing..." -ForegroundColor Cyan

# 1. Enforce Server SMB Signing
$srvRegPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $srvRegPath)) {
    New-Item -Path $srvRegPath -Force | Out-Null
}
Set-ItemProperty -Path $srvRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
Write-Host "SMB Server signing (always) enabled." -ForegroundColor Green

# 2. Enforce Client SMB Signing
$cliRegPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $cliRegPath)) {
    New-Item -Path $cliRegPath -Force | Out-Null
}
Set-ItemProperty -Path $cliRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
Write-Host "SMB Client signing (always) enabled." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-SMBSigningStatus.ps1](audit_scripts/Get-SMBSigningStatus.ps1)

```powershell
# Get-SMBSigningStatus.ps1
# Description: Audits the registry settings for SMB server and client signing.

Write-Host "--- Auditing SMB Message Signing ---" -ForegroundColor Cyan
$vulnerable = $false

# 1. Audit Server-side SMB Signing
$srvReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
if ($srvReg -and $srvReg.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Server signing is enforced (RequireSecuritySignature = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: SMB Server signing is NOT enforced." -ForegroundColor Red
    $vulnerable = $true
}

# 2. Audit Client-side SMB Signing
$cliReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
if ($cliReg -and $cliReg.RequireSecuritySignature -eq 1) {
    Write-Host "[+] SMB Client signing is enforced (RequireSecuritySignature = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: SMB Client signing is NOT enforced." -ForegroundColor Red
    $vulnerable = $true
}

if ($vulnerable) {
    Write-Host "Audit result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R13 (Disabling obsolete and insecure protocols and configuring transport security)
* **CIS Benchmark**: CIS Microsoft Windows Server Benchmark - Sections 2.3.9.2 and 2.3.9.5 (Ensure 'Microsoft network server/client: Digitally sign communications (always)' is set to 'Enabled')
* **Microsoft Security Guidance**: SMB Signing configurations and security implications
