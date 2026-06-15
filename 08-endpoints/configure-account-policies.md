# [REQ-END-018] Configure Account and Password Policies

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
    * `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
    * `Computer Configuration\Administrative Templates\System\PIN Complexity`
    * `Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
    * `Computer Configuration\Administrative Templates\Windows Components\Windows Hello for Business`
  * **Registry Locations**:
    * Configured via `GptTmpl.inf` (SecEdit System Access settings):
      * `MinimumPasswordLength` = `14` (14 characters minimum)
      * `PasswordComplexity` = `1` (Complexity enabled)
      * `PasswordHistorySize` = `24` (24 passwords remembered)
      * `MaxPasswordAge` = `0` (Password does not expire / disabled)
      * `MinPasswordAge` = `1` (1 day minimum)
      * `ClearTextPassword` = `0` (Reversible encryption disabled)
      * `RelaxMinPasswordLengthLimits` = `1` (Relax minimum password length limits enabled)
      * `AllowAdministratorLockout` = `1` (Allow Administrator account lockout enabled)
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
      * `ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)
      * `CachedLogonsCount` = `0` (REG_DWORD)
      * `PasswordExpiryWarning` = `14` (REG_DWORD, prompt user to change password before expiration)
    * `HKLM\SECURITY\Cache`
      * `NL$IterationCount` = `1954` (REG_DWORD, 1954 = 2,000,896 rounds of PBKDF2-SHA1)
    * `HKLM\System\CurrentControlSet\Control\Lsa`
      * `LimitBlankPasswordUse` = `1` (REG_DWORD)
      * `NoLMHash` = `1` (REG_DWORD)
      * `RestrictAnonymousSAM` = `1` (REG_DWORD, restrict anonymous enumeration of SAM)
      * `RestrictAnonymous` = `1` (REG_DWORD, restrict anonymous enumeration of shares)
      * `ForceNetworkLogon` = `0` (REG_DWORD, sharing and security model Classic)
      * `ObaseCaseInsensitive` = `1` (REG_DWORD, require case insensitivity for non-Windows subsystems)
    * `HKLM\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters`
      * `AllowPKU2U` = `0` (REG_DWORD, Allow PKU2U requests disabled)
    * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest`
      * `UseLogonCredential` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `AllowDomainPINLogon` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity`
      * `MinimumPINLength` = `6` (REG_DWORD)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
      * `MSAOptional` = `1` (REG_DWORD)
      * `MaxDevicePasswordFailedAttempts` = `10` (REG_DWORD, 10 or fewer invalid logon attempts, but not 0)
      * `CrashOnAuditFail` = `0` (REG_DWORD, shut down system if unable to log audits disabled)
      * `DisableCAD` = `0` (REG_DWORD, CTRL+ALT+DEL required)
      * `DontDisplayLastUserName` = `1` (REG_DWORD, Don't display last signed-in enabled)
    * `HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount`
      * `DisableUserAuth` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork`
      * `RequireSecurityDevice` = `1` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices`
      * `TPM12` = `0` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\Netlogon\Parameters`
      * `RequireSignOrSeal` = `1` (REG_DWORD)
      * `SealSecureChannel` = `1` (REG_DWORD)
      * `SignSecureChannel` = `1` (REG_DWORD)
      * `DisablePasswordChange` = `0` (REG_DWORD)
      * `MaximumPasswordAge` = `30` (REG_DWORD)
      * `RequireStrongKey` = `1` (REG_DWORD)
      * `ForceLogoffWhenHourExpire` = `1` (REG_DWORD, force logoff when logon hours expire enabled)
    * `HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters`
      * `EnablePlainTextPassword` = `0` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters`
      * `AutoDisconnect` = `15` (REG_DWORD, idle time before suspending session in minutes)
      * `EnableForcedLogoff` = `1` (REG_DWORD, disconnect clients when logon hours expire enabled)
      * `NullSessionShares` = `""` (REG_MULTI_SZ, shares that can be accessed anonymously -> none)
    * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0`
      * `allownullsessionfallback` = `0` (REG_DWORD)
      * `NTLMMinClientSec` = `537395200` (REG_DWORD)
      * `NTLMMinServerSec` = `537395200` (REG_DWORD)

---

## Rationale
Securing authentication parameters and account controls reduces the risk of password attacks and session hijackings:

1. **Account Lockout Threshold (`LockoutBadCount`)**: Brute-force and password-spraying attacks target user accounts to discover credentials. If no lockout threshold is configured, an attacker can make infinite password attempts. Configuring a lockout threshold of 10 bad attempts mitigates online brute-force attacks.
2. **Account Lockout Reset (`ResetLockoutCount`)**: This policy dictates how long the failed logon counter persists before resetting. Setting this to 15 minutes ensures that password attempts are restricted over time without introducing major helpdesk overhead.
3. **Reversible Encryption (`ClearTextPassword`)**: Storing passwords using reversible encryption is equivalent to storing cleartext passwords in the directory database. This key option exists only for legacy application support (such as CHAP authentication) and must be disabled to prevent database dumping/credential recovery.
4. **Local Password Complexity and Minimum Length (`MinimumPasswordLength`, `PasswordComplexity`)**: Setting the minimum password length to 14 characters and enabling complexity makes offline brute-force and dictionary attacks significantly harder. A length of 14 characters is the standard baseline recommended by ANSSI and CIS for general workstations.
5. **Password History and Age (`PasswordHistorySize`, `MaxPasswordAge`, `MinPasswordAge`)**: Mandating a history of 24 prevents users from cycling between a few similar passwords. Disabling password expiration (`MaxPasswordAge = 0`) aligns with NIST SP 800-63B and modern ANSSI guidelines. Since 14-character complex passwords are sufficiently robust, forcing periodic changes is deprecated as it often leads users to write down passwords or choose predictable variations. A minimum age of 1 day prevents users from immediately bypassing the history requirement by changing their password 24 times in succession.
4. **Smart Card Removal Behavior (`ScRemoveOption`)**: In secure environments using Smart Card or token-based authentication, removing the card must automatically lock the desktop session (`1`). If disabled, a user leaving their workstation with the card removed leaves the session exposed.
5. **Blank Passwords Limit (`LimitBlankPasswordUse`)**: Restricting the use of blank passwords to physical console logons prevents attackers from using empty-password accounts to authenticate remotely over network shares or RDP.
6. **Logon Caching Restriction (`CachedLogonsCount` = `0`) and Hashing Complexity (`NL$IterationCount` = `1954`)**: By default, Windows caches previous logons locally as MSCacheV2 hashes, derived using PBKDF2-SHA1. Setting `CachedLogonsCount` to `0` prevents the local storage of credentials for offline validation on standard workstations, forcing authentication against a DC. For systems where caching must be enabled (such as isolated member servers or laptops), the iteration count of the hashing algorithm should be increased using `NL$IterationCount`. Setting it to `1954` results in 2,000,896 rounds of PBKDF2-SHA1, dramatically increasing resistance to offline brute-force and GPU-accelerated cracking attacks (like RTX 4090 models).
7. **LSASS WDigest protection (`UseLogonCredential` = `0`)**: Disabling WDigest credential caching prevents the LSASS process from storing cleartext passwords in memory.
8. **Microsoft Account and PIN bans**: Restricting Microsoft consumer account authentication and domain PIN logons ensures that standard enterprise credentials and secure Hello for Business PINs are the only mechanisms used.
9. **Secure Channel and NTLM session security**: Forcing secure channel signing, disabling plain text passwords, preventing null session fallbacks, and requiring NTLMv2 and 128-bit encryption block legacy protocol exploitation.
10. **Kerberos Security Policy**: Restricting Kerberos ticket lifetimes (e.g. 10 hours max ticket lifetime, 7 days max renewal, 600 minutes max service ticket lifetime) and clock skew tolerance (5 minutes) limits the window of opportunity for stolen ticket abuse (Pass-the-Ticket) and ensures synchronization integrity.
11. **GPO Background Refresh Security**: Forcing regular Group Policy background reapplication prevents persistent local configuration changes or drift.
12. **WMI Class Minimization**: Avoiding WMI queries to `Win32_Product` avoids unintended re-installation checks of all MSI packages during GPO processing, protecting host CPU and disk health.
13. **GPO Commentary**: Requiring descriptive GPO comments ensures structural accountability and documentation parity.

---

## Legacy Impact & Compatibility
* **Account Lockouts**: Legitimate users who forget their passwords may lock themselves out. Standard procedures must exist for administrative reset of locked accounts.
* **Smart Card Removal**: Users must be trained to carry their smart cards with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.
* **Reversible Encryption**: Disabling reversible encryption may break legacy applications that rely on reading cleartext password equivalents. These applications should be modernized to support modern Kerberos or SAML/OIDC federations.
* **Minimum Password Length (14 characters)**: Users with short passwords will be forced to choose a longer password (at least 14 characters) during their next password change. Systems or service accounts with hardcoded shorter credentials must be updated before enforcing this policy.
* **No Password Expiration (MaxPasswordAge = 0)**: Users will no longer be prompted to periodically change their passwords, reducing helpdesk calls related to expired password lockouts and discouraging the use of weak incremental password schemes.
* **Logon Caching (CachedLogonsCount = 0)**: Workstations must have active, real-time connectivity to a Domain Controller to allow users to log on. Off-domain logons (e.g., users traveling or working offline without a pre-boot VPN connection) will fail. Remote users must use pre-boot VPN tunnels or alternate remote access architectures.
* **PBKDF2 Iteration Overhead**: Increasing the iteration count raises the CPU processing time required during logons that use cached credentials. A value of 1954 may introduce a slight delay (typically under 1 second) during interactive logins on older hardware.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Configure Lockout, Password and Kerberos Policies (Domain-wide)
These settings must be configured directly within the **Default Domain Policy** to apply domain-wide:
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the **Default Domain Policy**.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies`
4. Configure the settings:
   * **Account Lockout Policy**:
      * **Account lockout threshold**: `10` invalid logon attempts
      * **Reset account lockout counter after**: `15` minutes
      * **Account lockout duration**: `15` minutes (Must be greater than or equal to reset time)
      * **Allow Administrator account lockout**: `Enabled`
   * **Password Policy**:
     * **Enforce password history**: `24` passwords remembered
     * **Maximum password age**: `0` days (never expire)
     * **Minimum password age**: `1` day
     * **Minimum password length**: `14` characters
     * **Password must meet complexity requirements**: `Enabled`
     * **Store passwords using reversible encryption**: `Disabled`
     * **Relax minimum password length limits**: `Enabled`
   * **Kerberos Policy**:
     * **Enforce user logon restrictions**: `Enabled`
     * **Maximum lifetime for service ticket**: `600` minutes
     * **Maximum lifetime for user ticket**: `10` hours
     * **Maximum lifetime for user ticket renewal**: `7` days
     * **Maximum tolerance for computer clock synchronization**: `5` minutes

#### Step 2: Configure GPO Security Filtering & Delegation (MS16-072 Compliance)
Following the MS16-072 security update, user-scoped GPOs require computer accounts to have Read access to process the policy. When using Security Filtering to restrict GPOs to specific user groups:
1. In GPMC, select your user-targeted GPO.
2. Under the **Scope** tab, in the **Security Filtering** section, select **Authenticated Users** and click **Remove**.
3. Click **Add**, select your target user security group, and click **OK**.
4. Click on the **Delegation** tab.
5. Click **Add**, search for `Domain Computers` (change Object Types to include Computers), and click **OK**.
6. Set the permissions to **Read** and click **OK**.

#### Step 3: Group Policy WMI Filtering Best Practices
When using WMI filters to target GPOs:
* **DO NOT** query the `Win32_Product` WMI class. Calling this class triggers Windows Installer to perform a self-repair validation on every installed MSI package on the system, causing severe CPU spikes and delays during startup and logon. Use lightweight queries such as `Win32_OperatingSystem` instead.

#### Step 4: Mandate GPO Comments for Accountability
For all GPOs created, add a comment in the **Comment** tab of the GPO properties describing the purpose, author, date, and requirement ID.

#### Step 5: Configure Local Security Options
In the endpoints GPO (e.g., `GPO_Hardening_Workstations`), navigate to:
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
* **Policy**: `Interactive logon: Smart card removal behavior` -> Set to **Lock Workstation** (value 1)
* **Policy**: `Accounts: Limit local account use of blank passwords to console logon only` -> Set to **Enabled** (value 1)
* **Policy**: `Network security: Do not store LAN Manager hash value on next password change` -> Set to **Enabled** (value 1)
* **Policy**: `Interactive logon: Number of previous logons to cache (in case domain controller is not available)` -> Set to **0**
* **Policy**: `Network security: Minimum session security for NTLM SSP based (including secure RPC) clients` -> Set to **Require NTLMv2 session security, Require 128-bit encryption** (value 537395200)
* **Policy**: `Network security: Minimum session security for NTLM SSP based (including secure RPC) servers` -> Set to **Require NTLMv2 session security, Require 128-bit encryption** (value 537395200)
* **Policy**: `Network access: Allow anonymous SID/Name translation` -> Set to **Disabled** (value 0)
* **Policy**: `Network security: Allow LocalSystem NULL session fallback` -> Set to **Disabled** (value 0)
* **Policy**: `Interactive logon: Machine account lockout threshold` -> Set to **10** (or fewer invalid logon attempts, but not 0)
* **Policy**: `Audit: Shut down system immediately if unable to log security audits` -> Set to **Disabled** (value 0)
* **Policy**: `Interactive logon: Do not require CTRL+ALT+DEL` -> Set to **Disabled** (value 0)
* **Policy**: `Interactive logon: Don't display last signed-in` -> Set to **Enabled** (value 1)
* **Policy**: `Interactive logon: Prompt user to change password before expiration` -> Set to **14** days (or between 5 and 14 days)
* **Policy**: `Microsoft network client: Send unencrypted password to third-party SMB servers` -> Set to **Disabled** (value 0)
* **Policy**: `Microsoft network server: Amount of idle time required before suspending session` -> Set to **15** or fewer minutes
* **Policy**: `Microsoft network server: Disconnect clients when logon hours expire` -> Set to **Enabled** (value 1)
* **Policy**: `Network access: Do not allow anonymous enumeration of SAM accounts and shares` -> Set to **Enabled** (value 1)
* **Policy**: `Network access: Shares that can be accessed anonymously` -> Set to **None**
* **Policy**: `Network access: Sharing and security model for local accounts` -> Set to **Classic - local users authenticate as themselves**
* **Policy**: `Network Security: Allow PKU2U authentication requests to this computer to use online identities` -> Set to **Disabled** (value 0)
* **Policy**: `Network security: Force logoff when logon hours expire` -> Set to **Enabled** (value 1)
* **Policy**: `System objects: Require case insensitivity for non-Windows subsystems` -> Set to **Enabled** (value 1)

#### Step 3: Configure Hello for Business, PIN and Microsoft Account Policies
Navigate to:
`Computer Configuration\Administrative Templates\System\PIN Complexity`
* **Policy**: `Minimum PIN length` -> Set to **Enabled** with value **6**

Navigate to:
`Computer Configuration\Administrative Templates\Windows Components\Microsoft Account`
* **Policy**: `Block all consumer Microsoft account user authentication` -> Set to **Enabled**

Navigate to:
`Computer Configuration\Administrative Templates\Windows Components\Windows Hello for Business`
* **Policy**: `Use a hardware security device` -> Set to **Enabled**
* **Policy**: `Use convenience PIN sign-in` -> Set to **Disabled** (value 0)
* **Policy**: `Allow Microsoft accounts to be optional` -> Set to **Enabled** (value 1)

#### Step 4: Configure PBKDF2 Iteration Count via GPO Preferences
Since the PBKDF2 iteration count setting is not exposed in standard ADMX templates, deploy it via Registry GPO Preferences:
1. Within the endpoints GPO, navigate to:
   `Computer Configuration\Preferences\Windows Settings\Registry`
2. Right-click **Registry**, select **New** -> **Registry Item**.
3. Configure:
   * **Action**: `Update`
   * **Hive**: `HKEY_LOCAL_MACHINE`
   * **Key Path**: `SECURITY\Cache`
   * **Value name**: `NL$IterationCount`
   * **Value type**: `REG_DWORD`
   * **Value data**: `1954` (Decimal)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Enforce the local security settings and SecEdit configuration locally.

[Download Script: Set-AccountPolicies.ps1](implementation_scripts/Set-AccountPolicies.ps1)

```powershell
# Set-AccountPolicies.ps1
# Configures local account lockout, password parameters, smart card removal behavior, blank password blocks, Hello for Business, Microsoft accounts, secure channel options, and NTLM session security options.

Write-Host "Applying account and password policies..." -ForegroundColor Cyan

# 1. Enforce local security options via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String -Force
Set-ItemProperty -Path $WinlogonPath -Name "CachedLogonsCount" -Value 0 -Type DWord -Force
Write-Host "[+] Smart card removal behavior and logon caching configured." -ForegroundColor Green

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
Write-Host "[+] Blank password restriction and NoLMHash options enforced." -ForegroundColor Green

# LSASS WDigest caching block
$WDigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $WDigestPath)) {
    New-Item -Path $WDigestPath -Force | Out-Null
}
Set-ItemProperty -Path $WDigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force
Write-Host "[+] LSASS WDigest credential caching disabled." -ForegroundColor Green

# PBKDF2 Iterations for Cached Logons
$CachePath = "HKLM:\SECURITY\Cache"
if (-not (Test-Path $CachePath)) {
    New-Item -Path $CachePath -Force | Out-Null
}
Set-ItemProperty -Path $CachePath -Name "NL`$IterationCount" -Value 1954 -Type DWord -Force
Write-Host "[+] PBKDF2 cached credentials iteration count configured." -ForegroundColor Green

# Hello for Business, PIN and Microsoft Account policies
$SystemPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
if (-not (Test-Path $SystemPolicyPath)) {
    New-Item -Path $SystemPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPolicyPath -Name "AllowDomainPINLogon" -Value 0 -Type DWord -Force

$PinComplexityPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
if (-not (Test-Path $PinComplexityPath)) {
    New-Item -Path $PinComplexityPath -Force | Out-Null
}
Set-ItemProperty -Path $PinComplexityPath -Name "MinimumPINLength" -Value 6 -Type DWord -Force

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "MSAOptional" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Force

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path $MsaPath)) {
    New-Item -Path $MsaPath -Force | Out-Null
}
Set-ItemProperty -Path $MsaPath -Name "DisableUserAuth" -Value 1 -Type DWord -Force

$PassportPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
if (-not (Test-Path $PassportPath)) {
    New-Item -Path $PassportPath -Force | Out-Null
}
Set-ItemProperty -Path $PassportPath -Name "RequireSecurityDevice" -Value 1 -Type DWord -Force

$ExcludeDevicesPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices"
if (-not (Test-Path $ExcludeDevicesPath)) {
    New-Item -Path $ExcludeDevicesPath -Force | Out-Null
}
Set-ItemProperty -Path $ExcludeDevicesPath -Name "TPM12" -Value 0 -Type DWord -Force
Write-Host "[+] Hello for Business, PIN and Microsoft Account options configured." -ForegroundColor Green

# Domain Member Secure Channel netlogon settings
$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
if (-not (Test-Path $NetlogonPath)) {
    New-Item -Path $NetlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $NetlogonPath -Name "RequireSignOrSeal" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SealSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "SignSecureChannel" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "DisablePasswordChange" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "MaximumPasswordAge" -Value 30 -Type DWord -Force
Set-ItemProperty -Path $NetlogonPath -Name "RequireStrongKey" -Value 1 -Type DWord -Force
Write-Host "[+] Domain Member secure channel configurations applied." -ForegroundColor Green

# LanmanWorkstation plain text passwords block
$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (-not (Test-Path $LanmanWorkPath)) {
    New-Item -Path $LanmanWorkPath -Force | Out-Null
}
Set-ItemProperty -Path $LanmanWorkPath -Name "EnablePlainTextPassword" -Value 0 -Type DWord -Force

# NTLM SSP Client & Server security and Null Session Fallback
$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
if (-not (Test-Path $MsvPath)) {
    New-Item -Path $MsvPath -Force | Out-Null
}
Set-ItemProperty -Path $MsvPath -Name "allownullsessionfallback" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "NTLMMinClientSec" -Value 537395200 -Type DWord -Force
Set-ItemProperty -Path $MsvPath -Name "NTLMMinServerSec" -Value 537395200 -Type DWord -Force
Write-Host "[+] Network authentication security and NTLM session settings applied." -ForegroundColor Green

# Additional local security options for endpoints
$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPath)) {
    New-Item -Path $SystemPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPath -Name "CrashOnAuditFail" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "DisableCAD" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $SystemPath -Name "DontDisplayLastUserName" -Value 1 -Type DWord -Force

Set-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -Value 14 -Type DWord -Force

Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ForceNetworkLogon" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $LsaPath -Name "ObaseCaseInsensitive" -Value 1 -Type DWord -Force

$KerbParamsPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
if (-not (Test-Path $KerbParamsPath)) {
    New-Item -Path $KerbParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $KerbParamsPath -Name "AllowPKU2U" -Value 0 -Type DWord -Force

$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
if (-not (Test-Path $LanmanServerPath)) {
    New-Item -Path $LanmanServerPath -Force | Out-Null
}
Set-ItemProperty -Path $LanmanServerPath -Name "AutoDisconnect" -Value 15 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -Value @() -Type MultiString -Force

Set-ItemProperty -Path $NetlogonPath -Name "ForceLogoffWhenHourExpire" -Value 1 -Type DWord -Force
Write-Host "[+] Additional network and interactive security options applied." -ForegroundColor Green

# 2. Enforce Account Lockout and Password Policy via secedit
$SecTempDir = Join-Path $env:TEMP "AccountSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "account_sec.cfg"
$LogFile = Join-Path $SecTempDir "secedit.log"
$DbFile = Join-Path $SecTempDir "secedit.sdb"

# Export current db
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current configuration database."
    return
}

$ConfigText = Get-Content -Path $CfgFile -Raw
$HasSystemAccess = $ConfigText -match "\[System Access\]"
if (-not $HasSystemAccess) {
    $ConfigText += "`r`n[System Access]`r`n"
}

# Re-build [System Access] section line-by-line
$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InSystemAccess = $false

$AccountSettings = @{
    "LockoutBadCount"              = 10
    "ResetLockoutCount"            = 15
    "LockoutDuration"              = 15
    "ClearTextPassword"            = 0
    "MinimumPasswordLength"        = 14
    "PasswordComplexity"           = 1
    "PasswordHistorySize"          = 24
    "MaxPasswordAge"               = 0
    "MinPasswordAge"               = 1
    "RelaxMinPasswordLengthLimits" = 1
    "AllowAdministratorLockout"    = 1
    "MaxServiceTicketAge"          = 600
    "MaxTicketAge"                 = 10
    "MaxRenewAge"                  = 7
    "MaxClockSkew"                 = 5
    "TicketValidateClient"         = 1
}

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        $SectionName = $Matches[1]
        if ($SectionName -eq "System Access") {
            $InSystemAccess = $true
            $NewLines += $Line
            continue
        } else {
            $InSystemAccess = $false
        }
    }
    
    if ($InSystemAccess) {
        $IsManaged = $false
        foreach ($Key in $AccountSettings.Keys) {
            if ($Line -match "^\s*$($Key)\s*=") {
                $IsManaged = $true
                break
            }
        }
        if (-not $IsManaged) {
            $NewLines += $Line
        }
    } else {
        $NewLines += $Line
    }
}

# Append our settings
$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[System Access]") {
        foreach ($Key in $AccountSettings.Keys) {
            $Val = $AccountSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force

# Import
$Process = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "[+] Lockout and password policies applied locally." -ForegroundColor Green
} else {
    Write-Error "Failed to apply local account policies. Exit Code: $($Process.ExitCode)"
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
```

*To audit local account and password policies:*
[Download Script: Test-AccountPolicies.ps1](audit_scripts/Test-AccountPolicies.ps1)

```powershell
# Test-AccountPolicies.ps1
# Checks local registry and SecEdit settings for account lockout, password options, smart card removal behavior, PIN parameters, Hello for Business, Microsoft account settings, secure channel properties, and NTLM session configuration.

Write-Host "--- Auditing Account and Password Policies ---" -ForegroundColor Cyan

$script:Vulnerable = $false

# Helper function to audit registry properties
function Test-RegistryValue ($path, $name, $expectedValue) {
    $val = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    $actual = if ($val) { $val.$name } else { "" }
    $color = "Red"
    if ($actual -eq $expectedValue) {
        $color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - Registry Setting: $name | Actual: '$actual' (Expected: '$expectedValue')" -ForegroundColor $color
}

# 1. Audit Registry Settings
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
Test-RegistryValue $WinlogonPath "ScRemoveOption" "1"
Test-RegistryValue $WinlogonPath "CachedLogonsCount" 0

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
Test-RegistryValue $LsaPath "LimitBlankPasswordUse" 1
Test-RegistryValue $LsaPath "NoLMHash" 1

$WDigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
Test-RegistryValue $WDigestPath "UseLogonCredential" 0

$CachePath = "HKLM:\SECURITY\Cache"
Test-RegistryValue $CachePath "NL`$IterationCount" 1954

$SystemPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
Test-RegistryValue $SystemPolicyPath "AllowDomainPINLogon" 0

$PinComplexityPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity"
Test-RegistryValue $PinComplexityPath "MinimumPINLength" 6

$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Test-RegistryValue $SystemPath "MSAOptional" 1
Test-RegistryValue $SystemPath "MaxDevicePasswordFailedAttempts" 10

$MsaPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
Test-RegistryValue $MsaPath "DisableUserAuth" 1

$PassportPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork"
Test-RegistryValue $PassportPath "RequireSecurityDevice" 1

$ExcludeDevicesPath = "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices"
Test-RegistryValue $ExcludeDevicesPath "TPM12" 0

$NetlogonPath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
Test-RegistryValue $NetlogonPath "RequireSignOrSeal" 1
Test-RegistryValue $NetlogonPath "SealSecureChannel" 1
Test-RegistryValue $NetlogonPath "SignSecureChannel" 1
Test-RegistryValue $NetlogonPath "DisablePasswordChange" 0
Test-RegistryValue $NetlogonPath "MaximumPasswordAge" 30
Test-RegistryValue $NetlogonPath "RequireStrongKey" 1

$LanmanWorkPath = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
Test-RegistryValue $LanmanWorkPath "EnablePlainTextPassword" 0

$MsvPath = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"
Test-RegistryValue $MsvPath "allownullsessionfallback" 0
Test-RegistryValue $MsvPath "NTLMMinClientSec" 537395200
Test-RegistryValue $MsvPath "NTLMMinServerSec" 537395200

# Audit Additional security options
$SystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Test-RegistryValue $SystemPath "CrashOnAuditFail" 0
Test-RegistryValue $SystemPath "DisableCAD" 0
Test-RegistryValue $SystemPath "DontDisplayLastUserName" 1

Test-RegistryValue $WinlogonPath "PasswordExpiryWarning" 14

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
Test-RegistryValue $LsaPath "RestrictAnonymousSAM" 1
Test-RegistryValue $LsaPath "RestrictAnonymous" 1
Test-RegistryValue $LsaPath "ForceNetworkLogon" 0
Test-RegistryValue $LsaPath "ObaseCaseInsensitive" 1

$KerbParamsPath = "HKLM:\System\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
Test-RegistryValue $KerbParamsPath "AllowPKU2U" 0

$LanmanServerPath = "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters"
Test-RegistryValue $LanmanServerPath "AutoDisconnect" 15
Test-RegistryValue $LanmanServerPath "EnableForcedLogoff" 1

# Audit NullSessionShares
$NullSessionVal = Get-ItemProperty -Path $LanmanServerPath -Name "NullSessionShares" -ErrorAction SilentlyContinue
$NullSessionActual = if ($NullSessionVal) { $NullSessionVal.NullSessionShares } else { "" }
$NullSessionColor = "Red"
if ($null -eq $NullSessionActual -or $NullSessionActual -eq "" -or $NullSessionActual.Count -eq 0 -or ($NullSessionActual.Count -eq 1 -and $NullSessionActual[0] -eq "")) {
    $NullSessionColor = "Green"
} else {
    $script:Vulnerable = $true
}
Write-Host "    - Registry Setting: NullSessionShares | Actual: '$NullSessionActual' (Expected: empty/None)" -ForegroundColor $NullSessionColor

Test-RegistryValue $NetlogonPath "ForceLogoffWhenHourExpire" 1

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "AccountAuditSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "account_audit.cfg"
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current database."
    return
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
$AccountSettings = @{
    "LockoutBadCount"              = 10
    "ResetLockoutCount"            = 15
    "LockoutDuration"              = 15
    "ClearTextPassword"            = 0
    "MinimumPasswordLength"        = 14
    "PasswordComplexity"           = 1
    "PasswordHistorySize"          = 24
    "MaxPasswordAge"               = 0
    "MinPasswordAge"               = 1
    "RelaxMinPasswordLengthLimits" = 1
    "AllowAdministratorLockout"    = 1
    "MaxServiceTicketAge"          = 600
    "MaxTicketAge"                 = 10
    "MaxRenewAge"                  = 7
    "MaxClockSkew"                 = 5
    "TicketValidateClient"         = 1
}

foreach ($Key in $AccountSettings.Keys) {
    $Expected = $AccountSettings[$Key]
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    
    $Color = "Red"
    if ($Actual -eq [string]$Expected) {
        $Color = "Green"
    } else {
        $script:Vulnerable = $true
    }
    Write-Host "    - System Access Setting: $($Key) | Actual: '$($Actual)' (Expected: '$($Expected)')" -ForegroundColor $Color
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 2.3.2.2 (CrashOnAuditFail), Section 2.3.7.1 (DisableCAD), Section 2.3.7.2 (DontDisplayLastUserName), Section 2.3.7.3 (blank passwords), Section 2.3.7.8 (PasswordExpiryWarning), Section 2.3.9.1 (AutoDisconnect), Section 2.3.9.4 (EnableForcedLogoff), Section 2.3.9.5 (Smart card behavior), Section 2.3.10.3 (RestrictAnonymousSAM), Section 2.3.10.11 (NullSessionShares), Section 2.3.10.12 (ForceNetworkLogon), Section 2.3.11.3 (AllowPKU2U), Section 2.3.11.6 (ForceLogoffWhenHourExpire), Section 2.3.11.8 (anonymous translation), Section 2.3.11.10 (null session fallback), Section 2.3.15.1 (ObaseCaseInsensitive).
* **CIS Microsoft Windows 10/11 Client Benchmark**: Section 1.1.6 (RelaxMinPasswordLengthLimits), Section 1.2.3 (AllowAdministratorLockout).
* **ANSSI AD Hardening Guide**: Recommendations on password complexity, reversible encryption blocks, lockout management, and domain member secure channels.
* **DoD Windows 11 Computer STIG v2r6**: Various account policy, PIN complexity, Windows Hello for Business, Microsoft account restrictions, WDigest disabled, and Netlogon secure channel parameters.
