# Hardening Requirement: Enable Kerberos Armoring

## Target Scope
* **Applicable Systems**: Domain Controllers, Member Servers, Tier 2 Clients
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, Windows 10, Windows 11

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **KDC Settings (Domain Controllers)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\KDC`
    * **Policy**: `KDC support for claims, compound authentication and Kerberos armoring`
    * **Setting**: `Supported` (or `Fail unarmored authentication requests` for strict enforcement)
    * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters` -> `EnableCbacAndArmor` = `1` (Supported) or `3` (Fail unarmored) (REG_DWORD)
  * **Client Settings (Workstations & Member Servers)**:
    * **GPO Path**: `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
    * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring`
    * **Setting**: `Enabled`
    * **Registry Location**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` -> `EnableCbacAndArmor` = `1` (REG_DWORD)

---

## Rationale
Active Directory environments relying on standard Kerberos authentication are susceptible to offline brute-force, dictionary attacks, and credential harvesting. During the initial Kerberos pre-authentication phase, the client requests a Ticket Granting Ticket (TGT) in clear text by sending an AS-REQ containing encrypted timestamps. Attackers monitoring network traffic can intercept these exchanges, or perform AS-REP roasting against accounts that do not require pre-authentication, conducting offline password cracking to compromise credentials.

Kerberos Armoring, also known as Flexible Authentication Secure Tunneling (FAST), mitigates this vulnerability by establishing an encrypted channel (a secure tunnel) between the Kerberos client and the Key Distribution Center (KDC) on the Domain Controller. This tunnel is encrypted using the computer account's credential (or the local system's credential), protecting the pre-authentication messages (AS-REQ and AS-REP) from eavesdropping and tampering.

Additionally, Kerberos Armoring is a strict prerequisite for Dynamic Access Control (DAC) and Compound Authentication (which validates both the user's and the device's identities before granting access). Implementing Kerberos Armoring significantly enhances the directory service's resistance to credential relaying, user enumeration, and offline brute-force cracking.

---

## Legacy Impact & Compatibility
* **Operating System Requirements**: Kerberos Armoring requires at least a Windows Server 2012 domain functional level. Target clients and servers must run Windows 8 / Windows Server 2012 or newer.
* **Enforcement Risk**: Setting KDC support to "Fail unarmored authentication requests" (Value 3) too early will prevent systems that are not configured for FAST, legacy operating systems (e.g., Windows 7, Windows Server 2008 R2), and non-domain-joined devices from authenticating, resulting in complete denial of service.
* **Staged Deployment**: A phased rollout is highly recommended. Administrators must first configure all client systems to support claims and armoring. Once client compliance is verified, KDC support should be set to "Supported" (Value 1) to allow armored connections without failing unarmored ones. After validating the environment and verifying that no authentication errors occur, KDC support can be transitioned to "Fail unarmored authentication requests" (Value 3) for maximum security.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Configure Domain Controller KDC Policy
1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management host.
2. Edit the appropriate Domain Controllers hardening GPO (e.g., `GPO_Hardening_DomainControllers`).
3. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\KDC`
4. Configure the following setting:
   * **Policy**: `KDC support for claims, compound authentication and Kerberos armoring`
   * **Setting**: `Enabled`
   * **Options**: Select `Supported` from the dropdown list (upgrade to `Fail unarmored authentication requests` only after full client rollout and validation).
5. Link the GPO to the Domain Controllers Organizational Unit (OU).

#### Configure Client & Member Server Policy
1. In the **Group Policy Management Console**, edit the GPO applied to clients and member servers (e.g., `GPO_Hardening_Clients`).
2. Navigate to:
   `Computer Configuration\Policies\Administrative Templates\System\Kerberos`
3. Configure the following setting:
   * **Policy**: `Kerberos client support for claims, compound authentication and Kerberos armoring`
   * **Setting**: `Enabled`
4. Link the GPO to the appropriate OUs containing workstations and member servers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Use this method to apply the setting locally (for testing or standalone systems) or if the control is not manageable via standard GPO GUI interfaces.

```powershell
# Configure-KerberosArmoring.ps1
# Description: Configures Kerberos Armoring (FAST) registry settings on Domain Controllers and clients.

Write-Host "Applying hardening requirement: Enable Kerberos Armoring (FAST)..." -ForegroundColor Cyan

$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

# Configure client-side setting (applicable to all systems, including DCs)
if (-not (Test-Path $ClientRegPath)) {
    New-Item -Path $ClientRegPath -Force | Out-Null
}
Set-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
Write-Host "Client-side Kerberos Armoring enabled successfully." -ForegroundColor Green

# Determine if the host is a Domain Controller
$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)

if ($IsDC) {
    Write-Host "Domain Controller detected. Enabling KDC support for Kerberos Armoring..." -ForegroundColor Cyan
    if (-not (Test-Path $KdcRegPath)) {
        New-Item -Path $KdcRegPath -Force | Out-Null
    }
    
    # Value 1 = Supported (Safe deployment baseline)
    # Value 3 = Fail unarmored authentication requests (Strict/Enforced state)
    Set-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -Value 1 -Type DWord
    Write-Host "KDC support for claims and armoring set to Supported." -ForegroundColor Green
}
```

*To verify the setting has been applied:*
```powershell
# Get-KerberosArmoringStatus.ps1
# Description: Audits the Kerberos Armoring (FAST) configuration on DCs and clients.

Write-Host "--- Auditing Kerberos Armoring (FAST) Configuration ---" -ForegroundColor Cyan

$DomainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$IsDC = ($DomainRole -eq 4) -or ($DomainRole -eq 5)
$ClientRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$KdcRegPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters"

# 1. Audit Client-side support
$ClientValue = Get-ItemProperty -Path $ClientRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue

if ($null -ne $ClientValue) {
    $ClientState = $ClientValue.EnableCbacAndArmor
    if ($ClientState -eq 1) {
        Write-Host "[+] Client-side Kerberos Armoring is ENABLED (EnableCbacAndArmor = 1)." -ForegroundColor Green
    } else {
        Write-Host "[!] Client-side Kerberos Armoring is DISABLED (EnableCbacAndArmor = $($ClientState))." -ForegroundColor Red
    }
} else {
    Write-Host "[!] Client-side Kerberos Armoring configuration is MISSING (Disabled by default)." -ForegroundColor Red
}

# 2. Audit KDC support if Domain Controller
if ($IsDC) {
    Write-Host "Domain Controller detected. Auditing KDC support..." -ForegroundColor Cyan
    $KdcValue = Get-ItemProperty -Path $KdcRegPath -Name "EnableCbacAndArmor" -ErrorAction SilentlyContinue
    if ($null -ne $KdcValue) {
        $KdcState = $KdcValue.EnableCbacAndArmor
        if ($KdcState -eq 1) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Supported: 1)." -ForegroundColor Green
        } elseif ($KdcState -eq 2) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED (Always provide claims: 2)." -ForegroundColor Green
        } elseif ($KdcState -eq 3) {
            Write-Host "[+] KDC support for claims and armoring is ENABLED and ENFORCED (Fail unarmored: 3)." -ForegroundColor Green
        } else {
            Write-Host "[!] KDC support for claims and armoring is configured with unrecognized value: $($KdcState)." -ForegroundColor Red
        }
    } else {
        Write-Host "[!] KDC support for claims and armoring configuration is MISSING (Disabled by default)." -ForegroundColor Red
    }
}
```

---

## Sources & Compliance References
* **ANSSI AD Hardening Guide**: Recommendation R20 (Claims, compound authentication, and Kerberos armoring)
* **CIS Benchmark**: CIS Microsoft Windows Server 2016 Benchmark - Section 18.9.4.1 (Ensure 'KDC support for claims, compound authentication and Kerberos armoring' is configured) & Section 18.9.11.1 (Ensure 'Kerberos client support for claims, compound authentication and Kerberos armoring' is configured)
* **Microsoft Security Baseline Focus**: KDC and Kerberos Administrative Templates
