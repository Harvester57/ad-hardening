# [REQ-END-173] Account Policy: Domain Member Secure Channel Security for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Domain member: Digitally encrypt or sign secure channel data (always): `Enabled`
  * Domain member: Digitally encrypt secure channel data (when possible): `Enabled`
  * Domain member: Digitally sign secure channel data (when possible): `Enabled`
  * Domain member: Disable machine account password changes: `Disabled`
  * Domain member: Maximum machine account password age: `30` days
  * Domain member: Require strong (Windows 2000 or later) session key: `Enabled`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal` = `1` (REG_DWORD, Mandates signing or sealing of secure channel data)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel` = `1` (REG_DWORD, Enables encryption of secure channel data)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel` = `1` (REG_DWORD, Enables digital signing of secure channel data)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange` = `0` (REG_DWORD, Allows automatic machine account password rotation)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge` = `30` (REG_DWORD, Machine password must rotate every 30 days)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey` = `1` (REG_DWORD, Enforces 128-bit strong session key)
* **Vulnerability References**:
  * CVE References: CVE-2020-1472 (ZeroLogon)
  * MITRE ATT&CK: [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1003.004: OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/004/), [T1078.002: Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

---

## Rationale

The Netlogon secure channel provides the core trust link between enterprise workstations, member servers, and Active Directory Domain Controllers for user authentication, group enumeration, and secure channel key rotation. Hardening this channel prevents cryptographic downgrade, spoofing, and machine account persistence:

### Technical Threat Vectors and Defense Mechanics
1. **Preventing Man-in-the-Middle Tampering (`RequireSignOrSeal = 1`, `SealSecureChannel = 1`, `SignSecureChannel = 1`)**:
   Communication across the Netlogon Remote Protocol (MS-NRPC) handles sensitive authentication verification tokens. If encryption and signing are unconfigured or optional, an attacker on the local network segment can intercept Netlogon traffic, inspect NTLM validation exchanges, or inject forged authentication packets. Enforcing `RequireSignOrSeal = 1`, `SealSecureChannel = 1`, and `SignSecureChannel = 1` mandates end-to-end cryptographic sealing (AES/RC4 encryption) and digital signing (HMAC-SHA256) on every packet traversing the Netlogon RPC pipe.
2. **Blocking Cryptographic Downgrade Attacks (`RequireStrongKey = 1`)**:
   Historical implementations of MS-NRPC permitted negotiation of 56-bit DES session keys. Flaws in secure channel implementations, most notably the ZeroLogon vulnerability (CVE-2020-1472), highlighted how weak cryptographic key initialization could allow unauthenticated attackers to set machine passwords to blank and seize Domain Controller control. Enforcing `RequireStrongKey = 1` commands the endpoint to strictly require 128-bit session keys and terminate connection negotiations that fail to meet this standard.
3. **Automated Computer Password Rolling (`DisablePasswordChange = 0`, `MaximumPasswordAge = 30`)**:
   Every domain-joined computer account possesses a password stored locally in LSA secrets (`$MACHINE.ACC`). If password changes are disabled (`DisablePasswordChange = 1`), this password never rolls over. An attacker who dumps LSA secrets from an endpoint or backup image retains indefinite access to impersonate that machine on the network. Forcing automatic password rotation every 30 days (`MaximumPasswordAge = 30`) limits the lifespan of stolen machine secrets.
4. **Enterprise Defense Posture**:
   Across Tier 2 workstations and member servers, enforcing these Netlogon secure channel settings protects normal domain operations from network eavesdropping and ensures that machine credentials automatically expire.

---

## Legacy Impact & Compatibility

* **Modern Operating Systems**: Windows Server 2016+ and Windows 10/11 natively enforce secure channel signing and strong session keys. No disruption occurs across modern enterprise infrastructure.
* **Third-Party Domain Members (Linux / Appliance Integrations)**: Non-Windows devices joined to the domain via Samba or third-party AD integration packages (such as SSSD or Winbind) must support SMB signing and strong session keys (`client schannel = yes` in `smb.conf`).
* **Dormant Systems**: Laptops or member servers powered off for several months may occasionally encounter secure channel trust breaks if their computer password expires while offline. The secure channel can be repaired using `Test-ComputerSecureChannel -Repair` or `Reset-ComputerMachinePassword`.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Domain member: Digitally encrypt or sign secure channel data (always)**: Set to `Enabled`
   * **Domain member: Digitally encrypt secure channel data (when possible)**: Set to `Enabled`
   * **Domain member: Digitally sign secure channel data (when possible)**: Set to `Enabled`
   * **Domain member: Disable machine account password changes**: Set to `Disabled`
   * **Domain member: Maximum machine account password age**: Set to `30` days
   * **Domain member: Require strong (Windows 2000 or later) session key**: Set to `Enabled`
5. Link the GPO to the appropriate workstation and member server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountSecureChannel.ps1](../implementation_scripts/Configure-EndAccountSecureChannel.ps1)

```powershell
# Configure-EndAccountSecureChannel.ps1
# Description: Configures Netlogon secure channel signing, sealing, strong keys, and password rotation on Endpoints.

Write-Host "Configuring Endpoint Domain Member Secure Channel settings..." -ForegroundColor Cyan

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path -Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}

Set-ItemProperty -Path $NetlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force

Write-Host "Domain Member Secure Channel settings applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountSecureChannelStatus.ps1](../audit_scripts/Get-EndAccountSecureChannelStatus.ps1)

```powershell
# Get-EndAccountSecureChannelStatus.ps1
# Description: Audits Netlogon secure channel parameters on Endpoints.

Write-Host "--- Auditing Endpoint Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"

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

Test-RegVal $NetlogonPath "RequireSignOrSeal" 1
Test-RegVal $NetlogonPath "SealSecureChannel" 1
Test-RegVal $NetlogonPath "SignSecureChannel" 1
Test-RegVal $NetlogonPath "DisablePasswordChange" 0
Test-RegVal $NetlogonPath "MaximumPasswordAge" 30
Test-RegVal $NetlogonPath "RequireStrongKey" 1

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

Verify the active secure channel trust relationship using `nltest`:
```cmd
nltest /sc_query:%USERDNSDOMAIN%
nltest /sc_verify:%USERDNSDOMAIN%
```
Confirm that the status returns `NTRR_SUCCESS` (or `0x0`).

Verify the applied registry configuration using `reg query`:
```cmd
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireStrongKey
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge
```
Confirm that `RequireSignOrSeal` is `0x1`, `RequireStrongKey` is `0x1`, and `MaximumPasswordAge` is `0x1e` (Decimal `30`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.6.1 (Digitally encrypt or sign secure channel data), Section 2.3.6.2 (Digitally encrypt secure channel data), Section 2.3.6.3 (Digitally sign secure channel data), Section 2.3.6.4 (Disable machine account password changes = Disabled), Section 2.3.6.5 (Maximum machine account password age <= 30), Section 2.3.6.6 (Require strong session key)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.6.1 through 2.3.6.6
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.6.1 through 2.3.6.6
* **DoD Windows 11 Computer STIG**: Rule SV-220708r879608_rule (Machine account password age <= 30), Rule SV-220712r879612_rule (Require strong session key)
* **ANSSI Active Directory Hardening Guide**: Recommendations on secure channel integrity, strong session keys, and machine password rotation
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Domain Member Security Options
* **Related Controls**: [REQ-PAW-162: Account Policy: Domain Member Secure Channel Security for PAWs](../../07-paws/account-policy/configure-paw-account-secure-channel.md), [REQ-DC-032: Restrict Machine Account Quotas and Secure Channel on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
