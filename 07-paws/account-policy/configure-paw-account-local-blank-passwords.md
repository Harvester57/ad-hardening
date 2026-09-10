# [REQ-PAW-157] Account Policy: Local Accounts and Blank Password Restrictions for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Accounts: Limit local account use of blank passwords to console logon only: `Enabled`
  * Network security: Do not store LAN Manager hash value on next password change: `Enabled`
  * Network access: Sharing and security model for local accounts: `Classic - local users authenticate as themselves`
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse` = `1` (REG_DWORD, Blocks remote network authentication for accounts with blank passwords)
  * `HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash` = `1` (REG_DWORD, Prevents generation and storage of legacy LAN Manager hashes)
  * `HKLM\System\CurrentControlSet\Control\Lsa\ForceNetworkLogon` = `0` (REG_DWORD, Enforces Classic sharing where users authenticate as themselves)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1078.003: Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003/), [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/), [T1110.002: Password Cracking](https://attack.mitre.org/techniques/T1110/002/)

---

## Rationale

Restricting local account authentication boundaries, disabling legacy password hashes, and enforcing explicit user identity validation are vital to securing Tier 0 administrative workstations against remote compromise:

### Technical Threat Vectors and Defense Mechanics
1. **Confining Blank Password Accounts (`LimitBlankPasswordUse = 1`)**:
   If a local user or maintenance account is created without a password (or if a software installer provisions an account with an empty password), unhardened Windows systems permit that account to authenticate across the network via SMB, RPC, WinRM, or Remote Desktop. Attackers and automated lateral movement worms continuously scan endpoints for empty password accounts to gain unauthenticated remote shells. Configuring `LimitBlankPasswordUse = 1` strictly restricts blank password usage to the physical keyboard and monitor console, blocking all remote network logons.
2. **Preventing LAN Manager (LM) Hash Generation (`NoLMHash = 1`)**:
   The legacy LAN Manager (LM) hashing algorithm is fundamentally flawed:
   * It converts passwords to uppercase, reducing the character space from 95 printable ASCII characters to 69.
   * It splits the password into two independent 7-character halves.
   * Each half is encrypted separately using DES with a fixed key derived from the string `KGS!@#$%`.
   * Passwords with 7 or fewer characters yield a predictable, static second-half hash (`AAD3B435B51404EE`).
   Because each 7-character half can be cracked in seconds using precomputed rainbow tables or basic brute force, storing LM hashes in the Security Account Manager (SAM) database completely nullifies password length. Setting `NoLMHash = 1` prevents Windows from ever computing or writing LM hashes into the SAM hive or Active Directory when passwords are set or modified.
3. **Enforcing Classic Network Authentication Model (`ForceNetworkLogon = 0`)**:
   Windows supports two sharing models for local accounts: "Guest only" (`ForceNetworkLogon = 1`) and "Classic" (`ForceNetworkLogon = 0`). In Guest-only mode (originally designed for unmanaged home networks), all remote network logons are automatically mapped to the Guest account, bypassing granular NTFS permissions and preventing user-level audit accountability. Setting `ForceNetworkLogon = 0` enforces the Classic model: incoming network connections must authenticate as the specific local account, honoring discrete Access Control Lists (ACLs) and generating accurate Security event log attribution.
4. **Tier 0 PAW Local Account Lockdown**:
   PAWs must minimize local account reliance. Except for Windows LAPS-managed fallback administrator accounts, all administration is conducted using domain-managed Tier 0 smart card identities. Constraining blank password usage, purging LM hashes, and enforcing Classic authentication ensures that no shadow local account pathways can be exploited.

---

## Legacy Impact & Compatibility

* **Local Accounts without Passwords**: Any local account lacking a password will be immediately blocked from connecting via remote administrative tools (PowerShell Remoting, WinRM, SSH, RDP). Strong, unique passwords managed via Windows LAPS must be assigned to all local accounts.
* **Legacy Down-level Clients**: Disabling LM hashes breaks authentication from ancient non-NTLMv2 systems (such as Windows 95/98 or legacy DOS/OS2 network clients). These obsolete operating systems have zero operational presence in modern Tier 0 environments.
* **Pre-requisites**: Existing accounts that previously generated LM hashes will retain them in the SAM until their password is changed. Following policy deployment, all local account passwords must be rotated to purge any legacy LM hashes from the SAM database.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Accounts: Limit local account use of blank passwords to console logon only**: Set to `Enabled`
   * **Network security: Do not store LAN Manager hash value on next password change**: Set to `Enabled`
   * **Network access: Sharing and security model for local accounts**: Set to `Classic - local users authenticate as themselves`
5. Link the GPO to the dedicated PAW OU and force replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountLocalBlankPasswords.ps1](../implementation_scripts/Configure-PawAccountLocalBlankPasswords.ps1)

```powershell
# Configure-PawAccountLocalBlankPasswords.ps1
# Description: Enforces blank password restrictions, purges LM hashes, and sets Classic sharing on PAWs.

Write-Host "Configuring PAW local account and blank password restrictions..." -ForegroundColor Cyan

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

[Download Script: Get-PawAccountLocalBlankPasswordsStatus.ps1](../audit_scripts/Get-PawAccountLocalBlankPasswordsStatus.ps1)

```powershell
# Get-PawAccountLocalBlankPasswordsStatus.ps1
# Description: Audits local account restrictions, LM hash generation, and sharing model on PAWs.

Write-Host "--- Auditing PAW Local Account and Blank Password Restrictions ---" -ForegroundColor Cyan
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

Verify the applied settings using command prompt queries:
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
* **DoD Windows 11 Computer STIG**: Rule SV-220715r879615_rule (Limit blank password use), Rule SV-220733r879633_rule (Do not store LM hash), Rule SV-220730r879630_rule (Classic sharing model)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Disabling Deprecated LAN Manager Hashing and Hardening Local Accounts)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-168: Account Policy: Local Accounts and Blank Password Restrictions for Endpoints](../../08-endpoints/account-policy/configure-end-account-local-blank-passwords.md), [REQ-PAW-158: Account Policy: NTLM and LAN Manager Authentication Security for PAWs](configure-paw-account-ntlm-security.md)
