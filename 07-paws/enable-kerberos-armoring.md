# [REQ-PAW-167] Enable Kerberos Armoring for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10 Enterprise, Windows 11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
  * **Policies**:
    * `Kerberos client support for claims, compound authentication and Kerberos armoring` -> **Enabled**
    * `Support device authentication using certificate` -> **Enabled** (Automatic)
    * `Fail authentication requests when Kerberos armoring is not available` -> **Enabled**
  * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`
    * `EnableCbacAndArmor` = `1` (REG_DWORD)
    * `DevicePKInitEnabled` = `1` (REG_DWORD)
    * `DevicePKInitBehavior` = `0` (REG_DWORD)
    * `RequireFast` = `1` (REG_DWORD)

---

## Rationale
Privileged Access Workstations (PAWs) host high-privilege administrative sessions used to manage Active Directory Domain Controllers and Tier 0 identity infrastructure. Standard Kerberos pre-authentication transmits the initial authentication request (AS-REQ) containing timestamp data that can be intercepted by adversaries monitoring network traffic, facilitating offline dictionary attacks and password cracking. Furthermore, accounts configured without Kerberos pre-authentication (`DONT_REQ_PREAUTH`) remain susceptible to AS-REP roasting attacks.

Kerberos Armoring, or Flexible Authentication Secure Tunneling (FAST - RFC 6113), establishes an encrypted channel between the Kerberos client and the Key Distribution Center (KDC) using the client computer's account credential or machine certificate. This protects the AS-REQ and AS-REP exchanges against sniffing, offline cracking, and message tampering.

In accordance with Tier 0 hardening baselines, the PAW configuration is strictly tightened compared to standard end-user workstations. While standard endpoints negotiate FAST opportunistically, PAWs configure **Fail authentication requests when Kerberos armoring is not available** (`RequireFast = 1`). This policy mandates that all authentication service (AS) and ticket-granting service (TGS) exchanges must be armored. If a Domain Controller does not support FAST or an attacker attempts a protocol downgrade, authentication is immediately terminated, ensuring that Tier 0 credentials are never exposed over unarmored channels.

---

## Legacy Impact & Compatibility
* **Domain Controller Support Required**: Enabling `RequireFast = 1` requires all Domain Controllers in the domain to support Kerberos Armoring (`KDC support for claims, compound authentication and Kerberos armoring` set to `Supported` or higher). If applied before Domain Controllers are configured, PAW authentication will fail.
* **Administrative Scope**: Because PAWs are exclusively restricted to Tier 0 administrative management and prohibited from accessing untrusted external networks, third-party realms, or legacy application servers, enforcing strict armoring introduces zero operational impact to general business applications.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a Tier 0 management host.
2. Edit the dedicated PAW Computer Hardening GPO (e.g., `GPO_Hardening_PAW_Computers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
4. Configure the following settings:
   * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring` -> **Enabled**
   * **Policy**: `Support device authentication using certificate` -> **Enabled** (Select `Automatic` in options)
   * **Policy**: `Fail authentication requests when Kerberos armoring is not available` -> **Enabled**
5. Link the GPO to the **Tier 0 PAWs** Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for standalone PAW provisioning or gold image preparation) or if the control is not manageable via standard GPO interfaces.

[Download Script: Configure-PawKerberosArmoring.ps1](implementation_scripts/Configure-PawKerberosArmoring.ps1)

```powershell
# Configure-PawKerberosArmoring.ps1
# Description: Configures Kerberos Armoring (FAST) with strict enforcement and certificate device authentication on PAWs.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring (FAST) on PAWs..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}

# 1. Enable Kerberos client support for claims and armoring
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord

# 2. Support device authentication using certificate (Automatic)
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord

# 3. Fail authentication requests when Kerberos armoring is not available (Strict FAST enforcement on Tier 0 PAWs)
Set-ItemProperty -Path $ClientRegPath -Name "RequireFast" -Value 1 -Type DWord

Write-Host "PAW Kerberos Armoring configured successfully with strict enforcement (RequireFast = 1)." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-PawKerberosArmoringStatus.ps1](audit_scripts/Get-PawKerberosArmoringStatus.ps1)

```powershell
# Get-PawKerberosArmoringStatus.ps1
# Description: Audits Kerberos Armoring (FAST) configuration on Privileged Access Workstations (PAWs).

Write-Host "--- Auditing PAW Kerberos Armoring Configuration ---" -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$Vulnerable = $false

$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
$DevicePKInit = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -ErrorAction SilentlyContinue
$DeviceBehavior = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -ErrorAction SilentlyContinue
$RequireFast = Get-ItemProperty -Path $ClientRegPath -Name "RequireFast" -ErrorAction SilentlyContinue

# 1. Audit Client-side support for claims and armoring
if ($null -ne $ClientValue -and $ClientValue.EnableCbacAndArmor -eq 1) {
    Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Client-side Kerberos Armoring is DISABLED or missing." -ForegroundColor Red
    $Vulnerable = $true
}

# 2. Audit Certificate device authentication
if ($null -ne $DevicePKInit -and $DevicePKInit.DevicePKInitEnabled -eq 1 -and $null -ne $DeviceBehavior -and $DeviceBehavior.DevicePKInitBehavior -eq 0) {
    Write-Host "[+] Certificate device authentication is ENABLED: Automatic." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Certificate device authentication is not compliant or not configured." -ForegroundColor Red
    $Vulnerable = $true
}

# 3. Audit Strict Armoring Enforcement (RequireFast = 1)
if ($null -ne $RequireFast -and $RequireFast.RequireFast -eq 1) {
    Write-Host "[+] Strict Kerberos Armoring enforcement is ENABLED (RequireFast = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Strict Kerberos Armoring enforcement is NOT configured (RequireFast != 1)." -ForegroundColor Red
    $Vulnerable = $true
}

if ($Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R20 (Claims, compound authentication, and Kerberos armoring)
* **CIS Microsoft Windows Client Benchmark**: Section 18.9.11.1 (Ensure 'Kerberos client support for claims, compound authentication and Kerberos armoring' is configured), Section 18.9.11.2 (Ensure 'Support device authentication using certificate' is configured), Section 18.9.11.3 (Ensure 'Fail authentication requests when Kerberos armoring is not available' is configured)
* **RFC 6113**: Flexible Authentication Secure Tunneling (FAST)
* **Microsoft Security Baseline for Windows 10/11 Enterprise**: System\Kerberos Group Policy Object Definitions
