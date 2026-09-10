# [REQ-PAW-160] Account Policy: Windows Hello for Business and PIN Complexity for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> PIN Complexity / Windows Components -> Windows Hello for Business
* **Policy Settings**:
  * System\Logon: Turn on convenience PIN sign-in: `Disabled`
  * Windows Components\Windows Hello for Business: Use convenience PIN sign-in: `Disabled`
  * Windows Components\Windows Hello for Business: Use a hardware security device: `Enabled`
  * Windows Components\Windows Hello for Business: Allow Microsoft accounts to be optional: `Enabled`
  * System\PIN Complexity: Minimum PIN length: `Enabled` (`6` characters)
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon` = `0` (REG_DWORD, Convenience PIN logon disabled)
  * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength` = `6` (REG_DWORD, Minimum PIN length of 6 characters)
  * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\RequireSecurityDevice` = `1` (REG_DWORD, Requires TPM hardware security device)
  * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12` = `0` (REG_DWORD, Ensures TPM 1.2 is not preferred over TPM 2.0)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional` = `1` (REG_DWORD, Consumer Microsoft Account optional)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1556: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/), [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

---

## Rationale

Modern credential protection relies on hardware-bound asymmetric cryptographic tokens rather than reusable passwords. However, legacy convenience features and unhardened PIN mechanisms can undermine this architecture if not strictly configured on administrative workstations:

### Technical Threat Vectors and Defense Mechanics
1. **Convenience PIN vs Windows Hello for Business Asymmetric Cryptography**:
   A critical distinction exists between "Convenience PIN" and "Windows Hello for Business" (WHfB):
   * *Convenience PIN (`AllowDomainPINLogon = 1`)*: Simply acts as a local symmetric wrapper around the user's plaintext domain password, storing encrypted password blobs locally using DPAPI. If an adversary dumps system memory or gains SYSTEM access, the cached domain password can be extracted directly. Disabling convenience PINs (`AllowDomainPINLogon = 0`) eliminates this local password caching vulnerability.
   * *Windows Hello for Business (`PassportForWork`)*: Generates an asymmetric public-private key pair. The private key never leaves the hardware security boundary; the user's PIN merely authorizes the Hardware Security Module (TPM) to perform cryptographic signing operations on Kerberos or PKI authentication challenges.
2. **Mandating Hardware Security Devices (`RequireSecurityDevice = 1`)**:
   By default, if a compatible Trusted Platform Module (TPM) is unavailable, WHfB can fall back to software-based key storage (Software Key Storage Provider). A software-stored private key resides in the Windows file system and system memory, leaving it vulnerable to kernel-level memory scraping or offline registry theft. Enforcing `RequireSecurityDevice = 1` guarantees that WHfB keys are strictly minted and isolated inside a dedicated hardware TPM, preventing export or cloning even under local SYSTEM compromise.
3. **PIN Complexity & Anti-Hammering Protection (`MinimumPINLength = 6`)**:
   PINs are not transmitted over the network; they unlock the local TPM chip. Setting a minimum length of 6 digits, combined with the hardware TPM's built-in anti-hammering dictionary attack lockout counters, renders physical brute-force guessing mathematically infeasible.
4. **Decoupling from Consumer Accounts (`MSAOptional = 1`)**:
   Enabling `MSAOptional` ensures enterprise Windows Hello provisioning operates independently of consumer Microsoft Accounts, reinforcing the isolation of Tier 0 administrative operations from consumer cloud infrastructure.
5. **Tier 0 PAW Multi-Factor Authentication Architecture**:
   While physical FIDO2 / PIV smart card authentication remains the primary Tier 0 standard, where WHfB is utilized for PAW console logons, hardware-backed TPM 2.0 isolation and strict PIN complexity are mandatory to uphold administrative security boundaries.

---

## Legacy Impact & Compatibility

* **Hardware TPM 2.0 Requirement**: Endpoints lacking a compliant TPM 2.0 chip cannot enroll in Windows Hello for Business when `RequireSecurityDevice` is enforced. All PAW hardware platforms must meet modern secure hardware baselines (UEFI, TPM 2.0).
* **User Workflow Changes**: Administrators cannot configure simple 4-digit PINs. They will be prompted to choose a compliant PIN of at least 6 characters upon initial provisioning.
* **Convenience PIN Sign-In Disabled**: Users accustomed to legacy convenience PINs will be required to transition to enterprise WHfB or physical smart cards.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Configure System Logon policies:
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\System\Logon`
   * Double-click **Turn on convenience PIN sign-in** and set to **Disabled**.
4. Configure PIN Complexity policies:
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\System\PIN Complexity`
   * Double-click **Minimum PIN length**, set to **Enabled**, and enter `6`.
5. Configure Windows Hello for Business policies:
   * Navigate to: `Computer Configuration\Policies\Administrative Templates\Windows Components\Windows Hello for Business`
   * Double-click **Use a hardware security device** and set to **Enabled**.
   * Double-click **Use convenience PIN sign-in** and set to **Disabled**.
   * Double-click **Allow Microsoft accounts to be optional** and set to **Enabled**.
6. Link the GPO to the dedicated PAW OU and verify enforcement.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountHelloPin.ps1](../implementation_scripts/Configure-PawAccountHelloPin.ps1)

```powershell
# Configure-PawAccountHelloPin.ps1
# Description: Hardens Windows Hello for Business, disables convenience PINs, and mandates TPM hardware backing on PAWs.

Write-Host "Configuring PAW Windows Hello for Business and PIN policies..." -ForegroundColor Cyan

# 1. System Logon PIN Policy
$SysPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SysPath)) {
    New-Item -Path $SysPath -Force | Out-Null
}
Set-ItemProperty -Path $SysPath -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force

# 2. PIN Complexity
$PinPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
if (-not (Test-Path $PinPath)) {
    New-Item -Path $PinPath -Force | Out-Null
}
Set-ItemProperty -Path $PinPath -Name "MinimumPINLength" -Value 6 -Type DWord -Force

# 3. Hardware Security Device
$PfwPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (-not (Test-Path $PfwPath)) {
    New-Item -Path $PfwPath -Force | Out-Null
}
Set-ItemProperty -Path $PfwPath -Name "RequireSecurityDevice" -Value 1 -Type DWord -Force

$TpmPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices"
if (-not (Test-Path $TpmPath)) {
    New-Item -Path $TpmPath -Force | Out-Null
}
Set-ItemProperty -Path $TpmPath -Name "TPM12" -Value 0 -Type DWord -Force

# 4. MSA Optional
$SysPolPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SysPolPath)) {
    New-Item -Path $SysPolPath -Force | Out-Null
}
Set-ItemProperty -Path $SysPolPath -Name "MSAOptional" -Value 1 -Type DWord -Force

Write-Host "Windows Hello and PIN policies applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountHelloPinStatus.ps1](../audit_scripts/Get-PawAccountHelloPinStatus.ps1)

```powershell
# Get-PawAccountHelloPinStatus.ps1
# Description: Audits Windows Hello for Business, PIN complexity, and TPM enforcement status on PAWs.

Write-Host "--- Auditing PAW Windows Hello and PIN Policies ---" -ForegroundColor Cyan
$script:Vulnerable = $false

function Test-RegVal ($Path, $Name, $Expected) {
    if (-not (Test-Path -Path $Path)) {
        Write-Host "    [!] MISSING KEY: $Path" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $Path (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name under $Path is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
    }
}

Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon" 0
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" "MinimumPINLength" 6
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" "RequireSecurityDevice" 1
Test-RegVal "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices" "TPM12" 0
Test-RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional" 1

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied policies using command prompt queries:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon
reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v MinimumPINLength
reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v RequireSecurityDevice
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional
```
Confirm that `AllowDomainPINLogon` returns `0x0`, `MinimumPINLength` returns `0x6`, `RequireSecurityDevice` returns `0x1`, and `MSAOptional` returns `0x1`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.8.27.1 (Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'), Section 18.9.46.1 (Ensure 'Use a hardware security device' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.8.27.1, Section 18.9.46.1
* **DoD Windows 11 Computer STIG**: Rule SV-220799r879699_rule (Disabling convenience PIN sign-in), Rule SV-220800r879700_rule (Mandating TPM for WHfB)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Strong Authentication and Hardware Token Enforcement on PAWs)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Windows Hello for Business
* **Related Controls**: [REQ-END-171: Account Policy: Windows Hello for Business and PIN Complexity for Endpoints](../../08-endpoints/account-policy/configure-end-account-hello-pin.md), [REQ-PAW-155: Account Policy: Smart Card Removal Behavior for PAWs](configure-paw-account-smart-card-removal.md)
