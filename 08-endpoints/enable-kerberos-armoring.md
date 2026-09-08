# [REQ-END-178] Enable Kerberos Armoring for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations
* **Operating Systems**: Windows 10, Windows 11

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
  * **Policies**:
    * `Kerberos client support for claims, compound authentication and Kerberos armoring` -> **Enabled**
    * `Support device authentication using certificate` -> **Enabled** (Automatic)
    * `Fail authentication requests when Kerberos armoring is not available` -> **Disabled** (or Not Configured)
  * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`
    * `EnableCbacAndArmor` = `1` (REG_DWORD)
    * `DevicePKInitEnabled` = `1` (REG_DWORD)
    * `DevicePKInitBehavior` = `0` (REG_DWORD)
    * `RequireFast` = `0` (REG_DWORD)

---

## Rationale
Active Directory environments relying on standard Kerberos authentication are susceptible to offline brute-force, dictionary attacks, and credential harvesting. During standard Kerberos pre-authentication, the client sends an Authentication Service Request (AS-REQ) containing timestamp data encrypted with the user's password hash. Attackers monitoring network traffic can intercept these timestamps, or execute AS-REP roasting against accounts that do not require Kerberos pre-authentication (`DONT_REQ_PREAUTH`), conducting offline hash cracking to recover cleartext credentials.

Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST - RFC 6113), mitigates this vulnerability by establishing an encrypted channel between the client workstation and the Key Distribution Center (KDC) on the Domain Controller. This tunnel is encrypted using the computer account's credential (or machine certificate), protecting pre-authentication messages (AS-REQ and AS-REP) from eavesdropping, offline dictionary attacks, and message tampering.

On standard Tier 2 client workstations, Kerberos Armoring is configured for opportunistic negotiation (`RequireFast = 0`). This instructs the Windows Kerberos security provider to request armored exchanges whenever communicating with FAST-capable Domain Controllers, while maintaining backward compatibility with legacy resource servers, external forest trusts, and non-Windows Kerberos realms that do not yet support RFC 6113 FAST.

---

## Legacy Impact & Compatibility
* **Backward Compatibility**: Because `RequireFast` is set to `0` (or Not Configured), the client will gracefully negotiate standard unarmored Kerberos exchanges when authenticating to domain controllers or services that do not support FAST.
* **Operating System Requirements**: Client-side Kerberos Armoring requires Windows 8 / Windows 10 or newer. Standard domain-joined modern Windows endpoints seamlessly negotiate armored tunnels once the domain functional level is Windows Server 2012 or above.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on an administrative workstation.
2. Edit the workstation hardening GPO applied to standard clients (e.g., `GPO_Hardening_Workstations_Tier2`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
4. Configure the following settings:
   * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring` -> **Enabled**
   * **Policy**: `Support device authentication using certificate` -> **Enabled** (Select `Automatic` in options)
   * **Policy**: `Fail authentication requests when Kerberos armoring is not available` -> **Disabled** (or Not Configured)
5. Link the GPO to the appropriate Tier 2 Workstations Organizational Units (OUs).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing, non-domain scenarios, or standalone client deployment) or if the control is not manageable via standard GPO interfaces.

[Download Script: Configure-EndKerberosArmoring.ps1](implementation_scripts/Configure-EndKerberosArmoring.ps1)

```powershell
# Configure-EndKerberosArmoring.ps1
# Description: Configures client-side Kerberos Armoring (FAST) and certificate device authentication on Tier 2 client endpoints.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring on Tier 2 Endpoints..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"

if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}

# 1. Enable Kerberos client support for claims and armoring
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord

# 2. Support device authentication using certificate (Automatic)
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord

# 3. Ensure RequireFast is set to 0 (Opportunistic negotiation for general client workstations)
Set-ItemProperty -Path $ClientRegPath -Name "RequireFast" -Value 0 -Type DWord

Write-Host "Client endpoint Kerberos Armoring configured successfully." -ForegroundColor Green
```

*To verify the setting has been applied:*
[Download Script: Get-EndKerberosArmoringStatus.ps1](audit_scripts/Get-EndKerberosArmoringStatus.ps1)

```powershell
# Get-EndKerberosArmoringStatus.ps1
# Description: Audits client-side Kerberos Armoring configuration on Tier 2 endpoints.

Write-Host "--- Auditing Endpoint Kerberos Armoring Configuration ---" -ForegroundColor Cyan

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

# 3. Audit RequireFast (for endpoints, 0 or absent is acceptable for opportunistic FAST)
if ($null -eq $RequireFast -or $RequireFast.RequireFast -eq 0) {
    Write-Host "[+] Kerberos Armoring mode is configured for opportunistic negotiation (RequireFast = 0)." -ForegroundColor Green
} else {
    Write-Host "[-] Information: RequireFast is set to $($RequireFast.RequireFast)." -ForegroundColor Yellow
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
* **CIS Microsoft Windows Client Benchmark**: Section 18.9.11.1 (Ensure 'Kerberos client support for claims, compound authentication and Kerberos armoring' is configured), Section 18.9.11.2 (Ensure 'Support device authentication using certificate' is configured)
* **RFC 6113**: Flexible Authentication Secure Tunneling (FAST)
* **Microsoft Security Baseline Focus**: Kerberos Administrative Templates
