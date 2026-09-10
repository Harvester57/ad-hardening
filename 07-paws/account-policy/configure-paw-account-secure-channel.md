# [REQ-PAW-162] Account Policy: Domain Member Secure Channel Security for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

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
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
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

The Netlogon Remote Protocol (MS-NRPC) secure channel forms the cryptographic communication link between domain-joined workstations and Active Directory Domain Controllers. On Privileged Access Workstations, protecting this channel from tampering, session key downgrade, and credential stagnation is essential to directory integrity:

### Technical Threat Vectors and Defense Mechanics
1. **Mandatory Cryptographic Signing & Sealing (`RequireSignOrSeal = 1`, `SealSecureChannel = 1`, `SignSecureChannel = 1`)**:
   When a PAW authenticates an administrative session, validates Kerberos tickets, or updates computer passwords, the exchange traverses the Netlogon secure channel over RPC. If encryption (sealing) or message authentication (signing) is optional, a network adversary positioned between the PAW and Domain Controller can intercept NTLM challenge responses, inject spoofed RPC replies, or eavesdrop on sensitive account metadata. Mandating `RequireSignOrSeal = 1`, `SealSecureChannel = 1`, and `SignSecureChannel = 1` enforces end-to-end cryptographic sealing and SHA-based signing for all Netlogon traffic.
2. **Enforcing 128-Bit Session Keys (`RequireStrongKey = 1`)**:
   Legacy Netlogon implementations allowed negotiation of weak 56-bit DES session keys. Flaws in legacy cryptographic implementations (such as CVE-2020-1472 / ZeroLogon, which exploited flawed initialization vectors in Netlogon AES-CFB8 framing) demonstrated the catastrophic risk of unhardened secure channel negotiation. Enforcing `RequireStrongKey = 1` instructs the workstation to reject any connection that fails to negotiate a 128-bit strong session key.
3. **Automated Machine Password Rotation (`DisablePasswordChange = 0`, `MaximumPasswordAge = 30`)**:
   Every domain computer account (`$`) possesses a password stored in LSA secrets (`$MACHINE.ACC`). If computer password rotation is disabled (`DisablePasswordChange = 1`), the password remains static across the lifetime of the host. If an attacker dumps LSA secrets from a retired, backup, or compromised machine, they can impersonate the computer account indefinitely to query Active Directory. Enforcing periodic 30-day rotation (`MaximumPasswordAge = 30`) guarantees that machine secrets automatically expire and roll over.
4. **Tier 0 PAW Isolation Posture**:
   PAWs represent the administrative core of the directory. A compromised machine account belonging to a Tier 0 PAW could be leveraged to execute reconnaissance, query sensitive Active Directory objects, or request certificate templates. Fortifying the Netlogon secure channel and ensuring strict machine password rotation preserves Tier 0 boundaries.

---

## Legacy Impact & Compatibility

* **Modern Windows Compatibility**: Modern Windows 10/11 Enterprise systems natively support strong session keys and secure channel signing. Zero operational impact occurs on supported PAWs communicating with Windows Server 2016+ Domain Controllers.
* **Legacy Domain Controllers**: Domain controllers running unsupported Windows Server versions (Server 2003 or earlier) that cannot negotiate strong session keys will fail to establish secure channels. Such obsolete domain controllers are strictly prohibited in Tier 0 environments.
* **Offline Systems & Password Desynchronization**: If a PAW is kept powered off or disconnected for an extended period exceeding the machine password age (e.g., several months), its machine account password might desynchronize from Active Directory, requiring an administrator to reset the computer account using `Reset-ComputerMachinePassword`. Because PAWs should maintain continuous management network connectivity, this scenario is rare.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Domain member: Digitally encrypt or sign secure channel data (always)**: Set to `Enabled`
   * **Domain member: Digitally encrypt secure channel data (when possible)**: Set to `Enabled`
   * **Domain member: Digitally sign secure channel data (when possible)**: Set to `Enabled`
   * **Domain member: Disable machine account password changes**: Set to `Disabled`
   * **Domain member: Maximum machine account password age**: Set to `30` days
   * **Domain member: Require strong (Windows 2000 or later) session key**: Set to `Enabled`
5. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountSecureChannel.ps1](../implementation_scripts/Configure-PawAccountSecureChannel.ps1)

```powershell
# Configure-PawAccountSecureChannel.ps1
# Description: Configures Netlogon secure channel signing, sealing, strong keys, and password rotation on PAWs.

Write-Host "Configuring PAW Domain Member Secure Channel settings..." -ForegroundColor Cyan

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

[Download Script: Get-PawAccountSecureChannelStatus.ps1](../audit_scripts/Get-PawAccountSecureChannelStatus.ps1)

```powershell
# Get-PawAccountSecureChannelStatus.ps1
# Description: Audits Netlogon secure channel parameters on PAWs.

Write-Host "--- Auditing PAW Domain Member Secure Channel Settings ---" -ForegroundColor Cyan
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

Verify the active secure channel configuration using `nltest`:
```cmd
nltest /sc_query:%USERDNSDOMAIN%
nltest /sc_verify:%USERDNSDOMAIN%
```
Confirm that the secure channel is verified with a trusted Domain Controller and returns status `NTRR_SUCCESS` (or `0x0`).

Verify the applied registry settings using `reg query`:
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
* **DoD Windows 11 Computer STIG**: Rule SV-220708r879608_rule (Machine account password age <= 30), Rule SV-220712r879612_rule (Require strong session key)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Domain Member Secure Channel Integrity and ZeroLogon Mitigations)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Domain Member Security Options
* **Related Controls**: [REQ-END-173: Account Policy: Domain Member Secure Channel Security for Endpoints](../../08-endpoints/account-policy/configure-end-account-secure-channel.md), [REQ-DC-032: Restrict Machine Account Quotas and Secure Channel on Domain Controllers](../../02-domain-controllers/configure-security-options.md)
