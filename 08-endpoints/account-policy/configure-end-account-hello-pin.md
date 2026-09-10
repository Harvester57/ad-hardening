# [REQ-END-171] Account Policy: Windows Hello for Business and PIN Complexity for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

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
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
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

Deploying Windows Hello for Business (WHfB) across enterprise workstations transitions the environment from vulnerable password-based authentication to hardware-bound asymmetric cryptographic keys. However, strict policy constraints must be enforced to prevent weak PIN choices and insecure fallback mechanisms:

### Technical Threat Vectors and Defense Mechanics
1. **Eliminating Insecure Convenience PINs (`AllowDomainPINLogon = 0`)**:
   In older Windows releases or unmanaged setups, users can configure a "Convenience PIN". Convenience PINs do not generate cryptographic key pairs; instead, they encrypt the user's plaintext domain password and cache it locally in DPAPI storage. An adversary with administrative privileges or physical access can extract these cached credentials using memory dumping tools. Disabling convenience PIN sign-in forces users to utilize true Windows Hello for Business, where credentials cannot be extracted from disk or memory.
2. **Mandating Hardware TPM 2.0 Isolation (`RequireSecurityDevice = 1`)**:
   If hardware security devices are not strictly mandated, Windows Hello can fall back to software-based key storage (Software Key Storage Provider). Software keys reside in the file system and RAM, allowing an attacker who achieves SYSTEM execution to clone the private signing key. Configuring `RequireSecurityDevice = 1` enforces that all private keys are minted and permanently contained within the device's Trusted Platform Module (TPM), providing tamper-proof isolation.
3. **Enforcing PIN Complexity Thresholds (`MinimumPINLength = 6`)**:
   Unlike domain passwords that traverse the network, a WHfB PIN is strictly local to the endpoint and unlocks the local TPM. Setting a minimum length of 6 characters protects against shoulder surfing, smudge attacks on touchscreens, and rapid physical guessing. When combined with TPM hardware anti-hammering lockouts, brute-force PIN guessing is rendered impossible.
4. **Decoupling from Personal Consumer Accounts (`MSAOptional = 1`)**:
   Enabling `MSAOptional` allows enterprise domain users to provision and utilize Windows Hello for Business without connecting a personal consumer Microsoft Account, maintaining corporate identity governance.
5. **Endpoint Defense Posture**:
   Across enterprise workstations, replacing passwords with WHfB eliminates the primary attack vector for password spraying, phishing, and credential stuffing. Enforcing TPM 2.0 hardware backing ensures that even if an endpoint is compromised, the user's cryptographic identity cannot be exported to another device.

---

## Legacy Impact & Compatibility

* **Hardware TPM Requirement**: Workstations lacking a functional TPM 2.0 module cannot register or use Windows Hello for Business under this policy. Modern enterprise procurement standards should ensure all client hardware includes TPM 2.0.
* **User Onboarding Experience**: Users must select a PIN of at least 6 characters. Standard change management should educate users that their PIN unlocks the local hardware key and does not replace their domain password for non-WHfB network services.
* **Member Server Context**: Member servers generally utilize smart cards, LAPS, or Kerberos for administration and rarely utilize WHfB. Applying this policy ensures consistent security posture without operational impairment.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations (e.g., `GPO_Hardening_Endpoints`).
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
6. Link the GPO to the appropriate workstation Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountHelloPin.ps1](../implementation_scripts/Configure-EndAccountHelloPin.ps1)

```powershell
# Configure-EndAccountHelloPin.ps1
# Description: Hardens Windows Hello for Business, disables convenience PINs, and mandates TPM hardware backing on Endpoints.

Write-Host "Configuring Endpoint Windows Hello for Business and PIN policies..." -ForegroundColor Cyan

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

[Download Script: Get-EndAccountHelloPinStatus.ps1](../audit_scripts/Get-EndAccountHelloPinStatus.ps1)

```powershell
# Get-EndAccountHelloPinStatus.ps1
# Description: Audits Windows Hello for Business, PIN complexity, and TPM enforcement status on Endpoints.

Write-Host "--- Auditing Endpoint Windows Hello and PIN Policies ---" -ForegroundColor Cyan
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

Verify the applied policies using command line queries:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowDomainPINLogon
reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity" /v MinimumPINLength
reg query "HKLM\SOFTWARE\Policies\Microsoft\PassportForWork" /v RequireSecurityDevice
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MSAOptional
```
Confirm that `AllowDomainPINLogon` is `0x0`, `MinimumPINLength` is `0x6`, `RequireSecurityDevice` is `0x1`, and `MSAOptional` is `0x1`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 18.8.27.1 (Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'), Section 18.9.46.1 (Ensure 'Use a hardware security device' is set to 'Enabled')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 18.8.27.1, Section 18.9.46.1
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 18.8.27.1, Section 18.9.46.1
* **DoD Windows 11 Computer STIG**: Rule SV-220799r879699_rule (Disabling convenience PIN sign-in), Rule SV-220800r879700_rule (Mandating TPM for WHfB)
* **ANSSI Active Directory Hardening Guide**: Recommendations on strong authentication and hardware-backed credential protection
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Windows Hello for Business
* **Related Controls**: [REQ-PAW-160: Account Policy: Windows Hello for Business and PIN Complexity for PAWs](../../07-paws/account-policy/configure-paw-account-hello-pin.md), [REQ-END-166: Account Policy: Smart Card Removal Behavior for Endpoints](configure-end-account-smart-card-removal.md)
