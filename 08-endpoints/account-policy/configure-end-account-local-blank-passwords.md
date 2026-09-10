# [REQ-END-168] Account Policy: Local Accounts and Blank Password Restrictions for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Accounts: Limit local account use of blank passwords to console logon only: `Enabled`
  * Network security: Do not store LAN Manager hash value on next password change: `Enabled`
  * Network access: Sharing and security model for local accounts: `Classic - local users authenticate as themselves`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse` = `1` (REG_DWORD, Blocks remote network authentication for accounts with blank passwords)
  * `HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash` = `1` (REG_DWORD, Prevents generation and storage of legacy LAN Manager hashes)
  * `HKLM\System\CurrentControlSet\Control\Lsa\ForceNetworkLogon` = `0` (REG_DWORD, Enforces Classic sharing where users authenticate as themselves)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1078.003: Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/), [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/), [T1110.002: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)

---

## Rationale

Local accounts represent an attractive target for initial access and lateral movement across enterprise workstations. Restricting blank password usage, purging insecure LAN Manager hashes, and enforcing the Classic network authentication model hardens the local SAM perimeter across endpoints:

### Technical Threat Vectors and Defense Mechanics
1. **Neutralizing Blank Password Remote Exploitation (`LimitBlankPasswordUse = 1`)**:
   In unhardened environments, local accounts created without passwords (or third-party application service accounts installed with empty passwords) can be used to establish remote SMB sessions, invoke RPC interfaces, or connect via RDP. Automated worms and threat actors scan internal networks for blank-password administrative or support accounts. Setting `LimitBlankPasswordUse = 1` confines accounts with empty passwords strictly to the physical console logon, completely blocking all inbound network-based authentication attempts.
2. **Eliminating Cryptographically Broken LM Hashes (`NoLMHash = 1`)**:
   The LAN Manager (LM) password hashing algorithm, dating back to OS/2 and Windows NT, suffers from catastrophic architectural flaws:
   * It is case-insensitive, converting all lowercase characters to uppercase before hashing.
   * It bifurcates the password into two independent 7-byte segments.
   * Each 7-byte segment is encrypted separately with DES using a known static key derived from `KGS!@#$%`.
   * Passwords of 7 characters or fewer always yield the identical second-half hash constant `AAD3B435B51404EE`.
   As a result, an attacker who extracts the local SAM database can crack both halves of an LM hash within seconds using modest compute or lookup tables. Configuring `NoLMHash = 1` forces Windows to discard LM hash calculation and storage when accounts set or change passwords, retaining only stronger NTLMv2/NT hashes.
3. **Enforcing Account Accountability via Classic Sharing (`ForceNetworkLogon = 0`)**:
   Windows offers two security models for local account network logons: "Guest only" (`ForceNetworkLogon = 1`) and "Classic" (`ForceNetworkLogon = 0`). In Guest-only mode, any incoming connection using a local account is automatically demoted to the rights of the Guest account. While originally intended to simplify peer-to-peer sharing in home networks, this model obscures user identity, breaks granular NTFS discretionary access control lists (DACLs), and disrupts administrative tools like PowerShell Remoting and WinRM. Enforcing `ForceNetworkLogon = 0` requires callers to authenticate as the actual local account, ensuring rigorous access control and accurate Security event log attribution (Event ID 4624).
4. **Endpoint Defense Posture**:
   Across Tier 2 workstations and member servers, enforcing these controls stops opportunistic lateral traversal via unmanaged local accounts and ensures legacy authentication hashes cannot be scavenged from compromised endpoints.

---

## Legacy Impact & Compatibility

* **Blank Password Accounts**: Any service, local user, or scheduled task relying on an empty password will fail remote authentication over the network. Strong, unique passwords managed by Windows LAPS (Local Administrator Password Solution) must be provisioned.
* **Legacy Network Operating Systems**: Very old legacy devices (e.g., Windows 98 or non-Windows embedded appliances lacking NTLM support) cannot authenticate without LM hashes. Such systems must be isolated or decommissioned.
* **Password Change Requirement for Purge**: Setting `NoLMHash = 1` prevents new LM hashes from being generated, but does not automatically remove pre-existing LM hashes already written to the SAM database. A password rotation cycle for local accounts must be initiated following policy application.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Accounts: Limit local account use of blank passwords to console logon only**: Set to `Enabled`
   * **Network security: Do not store LAN Manager hash value on next password change**: Set to `Enabled`
   * **Network access: Sharing and security model for local accounts**: Set to `Classic - local users authenticate as themselves`
5. Link the GPO to the appropriate workstation and member server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountLocalBlankPasswords.ps1](../implementation_scripts/Configure-EndAccountLocalBlankPasswords.ps1)

```powershell
# Configure-EndAccountLocalBlankPasswords.ps1
# Description: Enforces blank password restrictions, purges LM hashes, and sets Classic sharing on Endpoints.

Write-Host "Configuring Endpoint local account and blank password restrictions..." -ForegroundColor Cyan

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path -Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}

Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ForceNetworkLogon" -Value 0 -Type DWord -Force

Write-Host "Local account and blank password restrictions applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountLocalBlankPasswordsStatus.ps1](../audit_scripts/Get-EndAccountLocalBlankPasswordsStatus.ps1)

```powershell
# Get-EndAccountLocalBlankPasswordsStatus.ps1
# Description: Audits local account restrictions, LM hash generation, and sharing model on Endpoints.

Write-Host "--- Auditing Endpoint Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"

function Test-RegVal ($Name, $Expected) {
    if (-not (Test-Path -Path $LsaPath)) {
        Write-Host "    [!] MISSING KEY: $LsaPath" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Prop = Get-ItemProperty -Path $LsaPath -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $Prop -or $null -eq $Prop.$Name) {
        Write-Host "    [!] MISSING VALUE: $Name under $LsaPath (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
        return
    }
    $Val = $Prop.$Name
    if ($Val -ne $Expected) {
        Write-Host "    [!] VULNERABLE: $Name is '$Val' (Expected: $Expected)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Name): $Val (Secure)" -ForegroundColor Green
    }
}

Test-RegVal "LimitBlankPasswordUse" 1
Test-RegVal "NoLMHash" 1
Test-RegVal "ForceNetworkLogon" 0

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

Verify the applied registry settings using command prompt queries:
```cmd
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v NoLMHash
reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v ForceNetworkLogon
```
Confirm that `LimitBlankPasswordUse` is `0x1`, `NoLMHash` is `0x1`, and `ForceNetworkLogon` is `0x0`.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.7.3 (Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'), Section 2.3.11.4 (Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'), Section 2.3.10.12 (Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic')
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.7.3, Section 2.3.11.4, Section 2.3.10.12
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.7.3, Section 2.3.11.4, Section 2.3.10.12
* **DoD Windows 11 Computer STIG**: Rule SV-220715r879615_rule (Limit blank password use), Rule SV-220733r879633_rule (Do not store LM hash), Rule SV-220730r879630_rule (Classic sharing model)
* **ANSSI Active Directory Hardening Guide**: Recommendations on eliminating legacy LM hashes and restricting local accounts
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-157: Account Policy: Local Accounts and Blank Password Restrictions for PAWs](../../07-paws/account-policy/configure-paw-account-local-blank-passwords.md), [REQ-END-169: Account Policy: NTLM and LAN Manager Authentication Security for Endpoints](configure-end-account-ntlm-security.md)
