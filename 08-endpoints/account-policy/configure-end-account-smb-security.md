# [REQ-END-174] Account Policy: SMB Client and Server Security Options for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options
* **Policy Settings**:
  * Microsoft network client: Send unencrypted password to third-party SMB servers: `Disabled`
  * Microsoft network server: Amount of idle time required before suspending session: `15` minutes
  * Microsoft network server: Disconnect clients when logon hours expire: `Enabled`
  * Network security: Force logoff when logon hours expire: `Enabled`
  * Network access: Shares that can be accessed anonymously: `None` (empty)
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **Registry Keys & Values**:
  * `HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword` = `0` (REG_DWORD, Prohibits cleartext passwords over SMB)
  * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\AutoDisconnect` = `15` (REG_DWORD, Suspends idle SMB sessions after 15 minutes)
  * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableForcedLogoff` = `1` (REG_DWORD, Disconnects SMB clients upon logon hours expiration)
  * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\ForceLogoffWhenHourExpire` = `1` (REG_DWORD, Forces session termination upon logon hours expiration)
  * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\NullSessionShares` = `@()` (REG_MULTI_SZ, Zero anonymous shares permitted)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1021.002: Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/), [T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/), [T1557.001: LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1557/001/)

---

## Rationale

The Server Message Block (SMB) protocol is integral to enterprise file sharing, administrative automation, and printer sharing. Hardening SMB client and server parameters protects against cleartext credential theft, resource exhaustion from dormant sessions, and anonymous file access:

### Technical Threat Vectors and Defense Mechanics
1. **Preventing Cleartext Credential Interception (`EnablePlainTextPassword = 0`)**:
   Certain third-party NAS storage appliances or non-standard SMB implementations do not support NTLMv2 or Kerberos and request plaintext authentication passwords across the wire. If a user or background process attempts to map an SMB share on a rogue device, the Windows SMB redirector could send credentials unencrypted. Setting `EnablePlainTextPassword = 0` forces the redirector to reject any unencrypted authentication request, preventing cleartext credential leakage.
2. **Auto-Disconnecting Idle SMB Sessions (`AutoDisconnect = 15`)**:
   Active SMB sessions maintain open TCP sockets, authenticated security tokens, and allocated memory structures in `srv2.sys`. In workstation and server environments, dormant sessions left unattended provide an avenue for session hijacking and lateral movement. Enforcing `AutoDisconnect = 15` automatically suspends idle SMB connections after 15 minutes, terminating dormant security contexts without impacting active file transfers.
3. **Enforcing Account Logon Schedules (`EnableForcedLogoff = 1`, `ForceLogoffWhenHourExpire = 1`)**:
   Active Directory enables administrators to configure allowed logon hours for user accounts (e.g., standard working hours). By default, if a user connects to an SMB file share during permitted hours and remains connected, Windows allows their session to persist past the expiration boundary. Enabling forced logoff mandates that the LanmanServer and Netlogon services terminate active SMB sessions and network connections when authorized logon hours expire, enforcing strict temporal governance.
4. **Purging Anonymous Shares (`NullSessionShares = @()`)**:
   The `NullSessionShares` parameter defines local share names accessible to unauthenticated callers (`ANONYMOUS LOGON`). Attackers scan corporate subnets to locate null session shares and harvest internal documents or plant unauthorized files. Emptying this registry entry ensures that every share on enterprise endpoints and member servers mandates valid domain authentication.
5. **Endpoint Security Posture**:
   Across Tier 2 endpoints, these settings reinforce network boundary hygiene and eliminate inadvertent credential exposure over common file sharing protocols.

---

## Legacy Impact & Compatibility

* **Third-Party File Storage**: Obsolete NAS devices requiring plaintext authentication will be inaccessible. All network file repositories must support NTLMv2 or Kerberos.
* **Scheduled Tasks Outside Logon Hours**: Service accounts and scheduled tasks configured to run after hours must have Active Directory logon hours configured to cover their operational windows; otherwise, active connections will be terminated.
* **Anonymous Access Blocked**: Legitimate workflows requiring anonymous file access are prohibited; all access must use authenticated user or service accounts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Microsoft network client: Send unencrypted password to third-party SMB servers**: Set to `Disabled`
   * **Microsoft network server: Amount of idle time required before suspending session**: Set to `15` minutes
   * **Microsoft network server: Disconnect clients when logon hours expire**: Set to `Enabled`
   * **Network security: Force logoff when logon hours expire**: Set to `Enabled`
   * **Network access: Shares that can be accessed anonymously**: Set to `None` (leave field completely empty)
5. Link the GPO to the appropriate workstation and member server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountSmbSecurity.ps1](../implementation_scripts/Configure-EndAccountSmbSecurity.ps1)

```powershell
# Configure-EndAccountSmbSecurity.ps1
# Description: Configures SMB client and server security options (plaintext block, auto-disconnect, logon hours) on Endpoints.

Write-Host "Configuring Endpoint SMB client and server security options..." -ForegroundColor Cyan

# 1. LanmanWorkstation: Block plaintext passwords
$WorkstationPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path -Path $WorkstationPath)) {
    New-Item -Path $WorkstationPath -Force | Out-Null
}
Set-ItemProperty -Path $WorkstationPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord -Force

# 2. LanmanServer: AutoDisconnect, EnableForcedLogoff, NullSessionShares
$ServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path -Path $ServerPath)) {
    New-Item -Path $ServerPath -Force | Out-Null
}
Set-ItemProperty -Path $ServerPath -Name "AutoDisconnect" -Value 15 -Type DWord -Force
Set-ItemProperty -Path $ServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $ServerPath -Name "NullSessionShares" -Value @() -Type MultiString -Force

# 3. Netlogon: ForceLogoffWhenHourExpire
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path -Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $NetlogonPath -Name "ForceLogoffWhenHourExpire" -Value 1 -Type DWord -Force

Write-Host "SMB client and server security options applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountSmbSecurityStatus.ps1](../audit_scripts/Get-EndAccountSmbSecurityStatus.ps1)

```powershell
# Get-EndAccountSmbSecurityStatus.ps1
# Description: Audits SMB client and server security options on Endpoints.

Write-Host "--- Auditing Endpoint SMB Client and Server Security Options ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$WorkstationPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$ServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
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

Test-RegVal $WorkstationPath "EnablePlainTextPassword" 0
Test-RegVal $ServerPath "AutoDisconnect" 15
Test-RegVal $ServerPath "EnableForcedLogoff" 1
Test-RegVal $NetlogonPath "ForceLogoffWhenHourExpire" 1

# Audit NullSessionShares
if (Test-Path -Path $ServerPath) {
    $NullShares = (Get-ItemProperty -Path $ServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue).NullSessionShares
    if ($null -ne $NullShares -and $NullShares.Count -gt 0 -and ($NullShares -join "") -ne "") {
        Write-Host "    [!] VULNERABLE: NullSessionShares contains: $($NullShares -join ', ')" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] NullSessionShares: Empty (Secure)" -ForegroundColor Green
    }
}

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

Verify the applied SMB settings using command prompt queries:
```cmd
reg query "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnablePlainTextPassword
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoDisconnect
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableForcedLogoff
reg query "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v ForceLogoffWhenHourExpire
reg query "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v NullSessionShares
```
Confirm that `EnablePlainTextPassword` is `0x0`, `AutoDisconnect` is `0xf` (Decimal `15`), `EnableForcedLogoff` is `0x1`, `ForceLogoffWhenHourExpire` is `0x1`, and `NullSessionShares` is empty.

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 2.3.8.1 (EnablePlainTextPassword = 0), Section 2.3.9.1 (AutoDisconnect <= 15), Section 2.3.9.2 (EnableForcedLogoff = 1), Section 2.3.11.1 (ForceLogoffWhenHourExpire = 1), Section 2.3.10.9 (NullSessionShares is empty)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 2.3.8.1, Section 2.3.9.1, Section 2.3.9.2, Section 2.3.11.1, Section 2.3.10.9
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 2.3.8.1, Section 2.3.9.1, Section 2.3.9.2, Section 2.3.11.1, Section 2.3.10.9
* **DoD Windows 11 Computer STIG**: Rule SV-220716r879616_rule (Plaintext password transmission), Rule SV-220718r879618_rule (AutoDisconnect idle time), Rule SV-220719r879619_rule (Disconnect clients when logon hours expire)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (SMB Client and Server Hardening)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-PAW-163: Account Policy: SMB Client and Server Security Options for PAWs](../../07-paws/account-policy/configure-paw-account-smb-security.md), [REQ-END-175: Account Policy: Anonymous Access and Enumeration Restrictions for Endpoints](configure-end-account-anonymous-restrictions.md)
