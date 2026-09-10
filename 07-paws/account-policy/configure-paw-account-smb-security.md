# [REQ-PAW-163] Account Policy: SMB Client and Server Security Options for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

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
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
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

The Server Message Block (SMB) protocol is utilized extensively for administrative file transfers, Group Policy retrieval, and remote management. Hardening SMB client and server parameters on Privileged Access Workstations prevents cleartext credential exposure, terminates stale dormant sessions, and eliminates unauthenticated network shares:

### Technical Threat Vectors and Defense Mechanics
1. **Preventing Cleartext Password Transmission (`EnablePlainTextPassword = 0`)**:
   Certain non-Microsoft or legacy SMB implementations lack support for NTLMv2 or Kerberos and prompt clients to transmit plaintext authentication strings across the wire. If an administrator connects to a rogue server or if an attacker spoofing an SMB endpoint solicits credentials, the LanmanWorkstation redirector could transmit unencrypted administrative passwords. Disabling `EnablePlainTextPassword` enforces that the SMB client strictly rejects any server request for unencrypted authentication, blocking plaintext password disclosure.
2. **Auto-Disconnecting Dormant SMB Sessions (`AutoDisconnect = 15`)**:
   Dormant SMB sessions retain open network handles, authenticated tokens, and server resources. On administrative systems, open SMB sessions left idle on management shares represent an opportunity for lateral movement and session hijacking over hijacked TCP sockets. Configuring `AutoDisconnect = 15` commands the SMB server engine to automatically disconnect idle sessions after 15 minutes of inactivity, terminating stale session contexts.
3. **Terminating Sessions Upon Logon Hours Expiry (`EnableForcedLogoff = 1`, `ForceLogoffWhenHourExpire = 1`)**:
   In high-assurance directory architectures, Tier 0 administrative accounts are restricted by defined logon schedules (e.g., standard business hours or designated maintenance change windows). By default in Windows, if an administrator is already logged on when their permitted hours expire, their active sessions remain open indefinitely. Enabling forced logoff policies commands both the LanmanServer service and the Netlogon service to forcefully terminate active network sessions the moment allowed hours expire, enforcing strict temporal authorization limits.
4. **Purging Anonymous Null Session Shares (`NullSessionShares = @()`)**:
   The `NullSessionShares` registry entry specifies local file shares that can be accessed by unauthenticated null sessions (`ANONYMOUS LOGON`). Threat actors scan internal networks for null session shares to read proprietary scripts, staging folders, or sensitive configuration files without credentials. Setting this value to an empty array ensures that zero shares on the PAW can be accessed without valid domain authentication.
5. **Tier 0 PAW Isolation Posture**:
   PAWs must not host unnecessary file shares, must never transmit cleartext credentials, and must enforce time-bounded administrative authorizations.

---

## Legacy Impact & Compatibility

* **Third-Party SMB Appliances**: Legacy network storage appliances requiring unencrypted SMB passwords will be blocked. PAWs must connect only to modern, encrypted SMBv3 shares hosted on supported Windows Server platforms.
* **Administrative Shift Windows**: Administrators performing emergency off-hours maintenance must ensure their accounts possess appropriate Active Directory logon hours permissions; otherwise, active sessions will be terminated automatically.
* **File Sharing from PAWs**: PAWs should not host general network file shares. Any temporary administrative file staging should occur via dedicated Tier 0 management repositories.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
4. Configure the following policies:
   * **Microsoft network client: Send unencrypted password to third-party SMB servers**: Set to `Disabled`
   * **Microsoft network server: Amount of idle time required before suspending session**: Set to `15` minutes
   * **Microsoft network server: Disconnect clients when logon hours expire**: Set to `Enabled`
   * **Network security: Force logoff when logon hours expire**: Set to `Enabled`
   * **Network access: Shares that can be accessed anonymously**: Set to `None` (leave field completely empty)
5. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountSmbSecurity.ps1](../implementation_scripts/Configure-PawAccountSmbSecurity.ps1)

```powershell
# Configure-PawAccountSmbSecurity.ps1
# Description: Configures SMB client and server security options (plaintext block, auto-disconnect, logon hours) on PAWs.

Write-Host "Configuring PAW SMB client and server security options..." -ForegroundColor Cyan

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

[Download Script: Get-PawAccountSmbSecurityStatus.ps1](../audit_scripts/Get-PawAccountSmbSecurityStatus.ps1)

```powershell
# Get-PawAccountSmbSecurityStatus.ps1
# Description: Audits SMB client and server security options on PAWs.

Write-Host "--- Auditing PAW SMB Client and Server Security Options ---" -ForegroundColor Cyan
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
* **DoD Windows 11 Computer STIG**: Rule SV-220716r879616_rule (Plaintext password transmission), Rule SV-220718r879618_rule (AutoDisconnect idle time), Rule SV-220719r879619_rule (Disconnect clients when logon hours expire)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (SMB Client Hardening and Protocol Security)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Local Policies Security Options
* **Related Controls**: [REQ-END-174: Account Policy: SMB Client and Server Security Options for Endpoints](../../08-endpoints/account-policy/configure-end-account-smb-security.md), [REQ-PAW-164: Account Policy: Anonymous Access and Enumeration Restrictions for PAWs](configure-paw-account-anonymous-restrictions.md)
