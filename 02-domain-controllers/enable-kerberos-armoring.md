# [REQ-DC-013] Enable Kerberos Armoring

## Target Scope
* **Applicable Systems**: Domain Controllers
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows Server 2025

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **KDC Settings (Domain Controllers)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\KDC`
    * **Policies**:
      * `KDC support for claims, compound authentication and Kerberos armoring` -> Enabled: Supported (or `Fail unarmored authentication requests` for strict enforcement)
      * `KDC support for PKInit Freshness Extension` -> Enabled: Supported
    * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters`
      * `EnableCbacAndArmor` = `1` (REG_DWORD)
      * `CbacAndArmorLevel` = `1` (REG_DWORD)
      * `PKINITFreshness` = `1` (REG_DWORD)
  * **Client Settings (Domain Controllers)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
    * **Policies**:
      * `Kerberos client support for claims, compound authentication and Kerberos armoring` -> Enabled
      * `Support device authentication using certificate` -> Enabled: Automatic
    * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters`
      * `EnableCbacAndArmor` = `1` (REG_DWORD)
      * `DevicePKInitEnabled` = `1` (REG_DWORD)
      * `DevicePKInitBehavior` = `0` (REG_DWORD)

---

## Rationale
Active Directory environments relying on standard Kerberos authentication are susceptible to offline brute-force, dictionary attacks, and credential harvesting. During the initial Kerberos pre-authentication phase, the client requests a Ticket Granting Ticket (TGT) in clear text by sending an AS-REQ containing encrypted timestamps. Attackers monitoring network traffic can intercept these exchanges, or perform AS-REP roasting against accounts that do not require pre-authentication, conducting offline password cracking to compromise credentials.

Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST - RFC 6113), mitigates this vulnerability by establishing an encrypted channel (a secure tunnel) between the Kerberos client and the Key Distribution Center (KDC) on the Domain Controller. This tunnel is encrypted using the computer account's credential (or the local system's credential), protecting the pre-authentication messages (AS-REQ and AS-REP) from eavesdropping, offline dictionary attacks, and tampering.

Additionally, Kerberos Armoring is a strict prerequisite for Dynamic Access Control (DAC), Compound Authentication (which validates both the user's and the device's identities before granting access), and Authentication Silos. On Windows Server 2016 and newer domain controllers, configuring KDC support for the PKInit Freshness Extension (RFC 8070) further strengthens public key authentication by ensuring that certificates cannot be reused in pre-authentication replay attacks.

Domain Controllers function both as KDC servers handling authentication requests and as Kerberos clients during domain controller replication, directory operations, and inter-forest authentication. Consequently, both KDC-side and client-side Kerberos armoring policies must be enabled on all Domain Controllers.

---

## Legacy Impact & Compatibility
* **Domain Functional Level Requirements**: Kerberos Armoring requires at least a Windows Server 2012 domain functional level (DFL). The PKInit Freshness Extension requires a Windows Server 2016 DFL.
* **Enforcement Risk**: Setting KDC support to "Fail unarmored authentication requests" (`CbacAndArmorLevel = 3`) too early will prevent systems that are not configured for FAST, legacy operating systems (e.g., Windows 7, Windows Server 2008 R2), and non-domain-joined devices from authenticating, resulting in denial of service.
* **Staged Deployment**: A phased rollout is required. Administrators must first configure all client systems and member servers to support claims and armoring. Once client compliance is verified across all tiers, KDC support should be set to "Supported" (`CbacAndArmorLevel = 1`) to allow armored connections without dropping unarmored requests. After complete validation and confirming that no authentication error events (Event ID 19 or Event ID 306 in the System log) occur, KDC support can be transitioned to "Fail unarmored authentication requests" (`CbacAndArmorLevel = 3`) for maximum security.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Configure Domain Controller KDC Policy
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a domain management workstation.
2. Edit the Domain Controllers hardening GPO linked to the **Domain Controllers** OU (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\KDC`
4. Configure the following settings:
   * **Policy**: `KDC support for claims, compound authentication and Kerberos armoring`
     * **Setting**: `Enabled`
     * **Options**: Select `Supported` from the dropdown list (upgrade to `Fail unarmored authentication requests` only after full client rollout and validation).
   * **Policy**: `KDC support for PKInit Freshness Extension`
     * **Setting**: `Enabled`
     * **Options**: Select `Supported` from the dropdown list.
5. Link the GPO to the Domain Controllers Organizational Unit.

#### Configure Domain Controller Client Policy
1. In the same Domain Controllers hardening GPO, navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
2. Configure the following settings:
   * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring` -> **Enabled**
   * **Policy**: `Support device authentication using certificate` -> **Enabled** (Select `Automatic` in options)
3. Ensure the GPO is enforced across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: Configure-KerberosArmoring.ps1](implementation_scripts/Configure-KerberosArmoring.ps1)

```powershell
# Configure-KerberosArmoring.ps1
# Description: Configures Kerberos Armoring (FAST) and PKInit Freshness Extension registry settings on Domain Controllers and Kerberos clients.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring (FAST) on Domain Controllers..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

# Configure client-side settings (applicable to all systems, including DCs for DC-to-DC authentication)
if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -Value 0 -Type DWord
Write-Host "Client-side Kerberos Armoring and Device Certificate Authentication enabled successfully." -ForegroundColor Green

# Determine if the host is a Domain Controller
$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)

if ($IsDC) {
    Write-Host "Domain Controller detected. Enabling KDC support for Kerberos Armoring and PKInit Freshness..." -ForegroundColor Cyan
    if (-not (Test-Path $KdcRegPath)) {
        New-Item -Path $KdcRegPath -Force | Out-Null
    }
    
    # Value 1 = Supported (Safe deployment baseline)
    # Value 3 = Fail unarmored authentication requests (Strict/Enforced state)
    Set-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
    Set-ItemProperty -Path $KdcRegPath -Name "CbacAndArmorLevel" -Value 1 -Type DWord
    # Value 1 = Supported for PKInit Freshness Extension (RFC 8070)
    Set-ItemProperty -Path $KdcRegPath -Name "PKINITFreshness" -Value 1 -Type DWord
    Write-Host "KDC support for claims, armoring (Supported: 1), and PKInit Freshness enabled successfully." -ForegroundColor Green
}
```

*To verify the setting has been applied:*
[Download Script: Get-KerberosArmoringStatus.ps1](audit_scripts/Get-KerberosArmoringStatus.ps1)

```powershell
# Get-KerberosArmoringStatus.ps1
# Description: Audits the Kerberos Armoring (FAST) and PKInit Freshness configuration on Domain Controllers and clients.

Write-Host "--- Auditing Kerberos Armoring (FAST) Configuration ---" -ForegroundColor Cyan

$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)
$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

$Vulnerable = $false

# 1. Audit Client-side support
$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
$DevicePKInit = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitEnabled" -ErrorAction SilentlyContinue
$DeviceBehavior = Get-ItemProperty -Path $ClientRegPath -Name "DevicePKInitBehavior" -ErrorAction SilentlyContinue

if ($null -ne $ClientValue -and $ClientValue.EnableCbacAndArmor -eq 1) {
    Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Client-side Kerberos Armoring is DISABLED or missing." -ForegroundColor Red
    $Vulnerable = $true
}

if ($null -ne $DevicePKInit -and $DevicePKInit.DevicePKInitEnabled -eq 1 -and $null -ne $DeviceBehavior -and $DeviceBehavior.DevicePKInitBehavior -eq 0) {
    Write-Host "[+] Certificate device authentication is ENABLED: Automatic." -ForegroundColor Green
} else {
    Write-Host "[!] VULNERABLE: Certificate device authentication is not compliant or not configured." -ForegroundColor Red
    $Vulnerable = $true
}

# 2. Audit KDC support if Domain Controller
if ($IsDC) {
    Write-Host "Domain Controller detected. Auditing KDC support..." -ForegroundColor Cyan
    $KdcCbac = Get-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
    $KdcLevel = Get-ItemProperty -Path $KdcRegPath -Name "CbacAndArmorLevel" -ErrorAction SilentlyContinue
    $KdcFresh = Get-ItemProperty -Path $KdcRegPath -Name "PKINITFreshness" -ErrorAction SilentlyContinue

    if ($null -ne $KdcCbac -and $KdcCbac.EnableCbacAndArmor -eq 1 -and $null -ne $KdcLevel) {
        $LevelVal = $KdcLevel.CbacAndArmorLevel
        if ($LevelVal -eq 1) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Supported: 1)." -ForegroundColor Green
        } elseif ($LevelVal -eq 2) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Always provide claims: 2)." -ForegroundColor Green
        } elseif ($LevelVal -eq 3) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED and ENFORCED (Fail unarmored: 3)." -ForegroundColor Green
        } else {
            Write-Host "[!] VULNERABLE: KDC CbacAndArmorLevel configured with invalid value: $($LevelVal)." -ForegroundColor Red
            $Vulnerable = $true
        }
    } else {
        Write-Host "[!] VULNERABLE: KDC support for claims and armoring is MISSING or misconfigured." -ForegroundColor Red
        $Vulnerable = $true
    }

    if ($null -ne $KdcFresh -and ($KdcFresh.PKINITFreshness -eq 1 -or $KdcFresh.PKINITFreshness -eq 2)) {
        Write-Host "[+] KDC PKInit Freshness Extension is ENABLED (Value: $($KdcFresh.PKINITFreshness))." -ForegroundColor Green
    } else {
        Write-Host "[!] VULNERABLE: KDC PKInit Freshness Extension is MISSING or disabled." -ForegroundColor Red
        $Vulnerable = $true
    }
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
* **CIS Microsoft Windows Server Benchmark**: Section 18.9.4.1 (Ensure 'KDC support for claims, compound authentication and Kerberos armoring' is configured), Section 18.9.4.3 (Ensure 'KDC support for PKInit Freshness Extension' is configured), Section 18.9.11.1 (Ensure 'Kerberos client support for claims, compound authentication and Kerberos armoring' is configured), Section 18.9.11.2 (Ensure 'Support device authentication using certificate' is configured)
* **RFC 6113**: Flexible Authentication Secure Tunneling (FAST)
* **RFC 8070**: Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) Freshness Extension
* **Microsoft Security Baseline Focus**: KDC and Kerberos Administrative Templates
