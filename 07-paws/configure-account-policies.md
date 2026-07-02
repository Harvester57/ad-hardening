# [REQ-PAW-013] Configure Account and Password Policies for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

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
      * `MinimumPasswordLength` = `20` (20 characters minimum)
      * `PasswordComplexity` = `1` (Complexity enabled)
      * `PasswordHistorySize` = `24` (24 passwords remembered)
      * `MaxPasswordAge` = `0` (Password does not expire / disabled)
      * `MinPasswordAge` = `1` (1 day minimum)
      * `ClearTextPassword` = `0` (Reversible encryption disabled)
      * `LockoutBadCount` = `5` (5 invalid logon attempts allowed)
      * `ResetLockoutCount` = `30` (30 minutes lockout observation window)
      * `LockoutDuration` = `30` (30 minutes lockout duration)
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
      * `ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)
      * `CachedLogonsCount` = `0` (REG_DWORD)
    * `HKLM\SECURITY\Cache`
      * `NL$IterationCount` = `1954` (REG_DWORD, 1954 = 2,000,896 rounds of PBKDF2-SHA1)
    * `HKLM\System\CurrentControlSet\Control\Lsa`
      * `LimitBlankPasswordUse` = `1` (REG_DWORD)
      * `NoLMHash` = `1` (REG_DWORD)
      * `LmCompatibilityLevel` = `5` (REG_DWORD, Network security: LAN Manager authentication level - NTLMv2 only)
    * `HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest`
      * `UseLogonCredential` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
      * `AllowDomainPINLogon` = `0` (REG_DWORD)
    * `HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity`
      * `MinimumPINLength` = `6` (REG_DWORD)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
      * `MSAOptional` = `1` (REG_DWORD)
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
    * `HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters`
      * `EnablePlainTextPassword` = `0` (REG_DWORD)
    * `HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0`
      * `allownullsessionfallback` = `0` (REG_DWORD)
      * `NTLMMinClientSec` = `537395200` (REG_DWORD)
      * `NTLMMinServerSec` = `537395200` (REG_DWORD)

---

## Rationale
Securing authentication parameters and account controls reduces the risk of password attacks and session hijackings on high-value administrative endpoints:

1. **Stricter Lockout Threshold (`LockoutBadCount`)**: For PAWs, the lockout threshold is reduced to 5 attempts (compared to 10 for standard endpoints). This is necessary because PAWs are used exclusively by Tier 0 administrators, who are high-value targets. A stricter threshold prevents brute-force attempts on local fallback accounts.
2. **Robust Local Password Settings (`MinimumPasswordLength`, `PasswordComplexity`)**: Local accounts on PAWs (such as fallback administrators) must use passwords of at least 20 characters with complexity enabled. This mitigates offline password cracking if database hashes or local SAM registries are dumped.
3. **No Password Expiration (`MaxPasswordAge = 0`)**: Periodic password expiration is disabled. Setting the password expiration interval to 0 prevents users from cycling to weaker password variants or writing credentials down, as a 20-character complex password is mathematically robust against current brute-forcing capabilities.
4. **Smart Card Removal Behavior (`ScRemoveOption`)**: In secure environments using Smart Card or token-based authentication, removing the card must automatically lock the desktop session (`1`). If disabled, a user leaving their workstation with the card removed leaves the session exposed.
5. **Blank Passwords Limit (`LimitBlankPasswordUse`)**: Restricting the use of blank passwords to physical console logons prevents attackers from using empty-password accounts to authenticate remotely over network shares or RDP.
6. **Logon Caching Restriction (`CachedLogonsCount` = `0`) and Hashing Complexity (`NL$IterationCount` = `1954`)**: By default, Windows caches previous logons locally as MSCacheV2 hashes, derived using PBKDF2-SHA1. Setting `CachedLogonsCount` to `0` prevents the local storage of credentials for offline validation on standard workstations, forcing authentication against a DC. For systems where caching must be enabled (such as isolated member servers or laptops), the iteration count of the hashing algorithm should be increased using `NL$IterationCount`. Setting it to `1954` results in 2,000,896 rounds of PBKDF2-SHA1, increasing resistance to offline brute-force and GPU-accelerated cracking attacks.
7. **LSASS WDigest protection (`UseLogonCredential` = `0`)**: Disabling WDigest credential caching prevents the LSASS process from storing cleartext passwords in memory.
8. **Microsoft Account and PIN bans**: Restricting Microsoft consumer account authentication and domain PIN logons ensures that standard enterprise credentials and secure Hello for Business PINs are the only mechanisms used.
9. **Secure Channel and NTLM session security**: Forcing secure channel signing, disabling plain text passwords, preventing null session fallbacks, requiring NTLMv2 and 128-bit encryption, and enforcing client-side NTLMv2-only authentication via `LmCompatibilityLevel = 5` block legacy protocol exploitation and relay vectors.
10. **Fine-Grained Password Policies (FGPP)**: While local accounts are secured on the machine, the Active Directory user accounts of the Tier 0 Administrators who logon to these PAWs must also be protected by a domain-level Fine-Grained Password Policy (FGPP / PSO) of at least 20 characters, as configured in [REQ-ID-001 - Enforce Fine-Grained Password Policies](../03-identities-services/enforce-fgpp.md).

---

## Legacy Impact & Compatibility
* **Account Lockouts**: Legitimate administrators who forget their passwords may lock themselves out. Standard procedures must exist for administrative reset of locked accounts by another Tier 0 administrator.
* **Smart Card Removal**: Administrators must be trained to carry their smart cards with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.
* **Reversible Encryption**: Disabling reversible encryption may break legacy applications that rely on reading cleartext password equivalents. These applications should not exist in the Tier 0 environment.
* **Logon Caching (CachedLogonsCount = 0)**: PAWs must have active, real-time connectivity to a Domain Controller to allow users to log on. Off-domain logons (e.g., users traveling or working offline without a pre-boot VPN connection) will fail. Remote users must use pre-boot VPN tunnels or alternate remote access architectures.
* **No Password Expiration**: Removing periodic password changes minimizes helpdesk tickets and stops administrators from choosing predictable increments. However, the organization must still enforce credential revocation and manual rotation protocols in the event of a suspected credential leak.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Configure Lockout and Password Policies (Domain-wide or PAW GPO)
These settings must be configured in a dedicated GPO linked to the PAW Organizational Unit (OU) (e.g., `GPO_Hardening_PAWs`):
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies`
4. Configure the settings:
   * **Account Lockout Policy**:
     * **Account lockout threshold**: `5` invalid logon attempts
     * **Reset account lockout counter after**: `30` minutes
     * **Account lockout duration**: `30` minutes
   * **Password Policy**:
     * **Enforce password history**: `24` passwords remembered
     * **Maximum password age**: `0` days (never expire)
     * **Minimum password age**: `1` day
     * **Minimum password length**: `20` characters
     * **Password must meet complexity requirements**: `Enabled`
     * **Store passwords using reversible encryption**: `Disabled`

#### Step 2: Configure Local Security Options
In the PAW GPO, navigate to:
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
* **Policy**: `Interactive logon: Smart card removal behavior` -> Set to **Lock Workstation** (value 1)
* **Policy**: `Accounts: Limit local account use of blank passwords to console logon only` -> Set to **Enabled** (value 1)
* **Policy**: `Network security: Do not store LAN Manager hash value on next password change` -> Set to **Enabled** (value 1)
* **Policy**: `Interactive logon: Number of previous logons to cache (in case domain controller is not available)` -> Set to **0**
* **Policy**: `Network security: Minimum session security for NTLM SSP based (including secure RPC) clients` -> Set to **Require NTLMv2 session security, Require 128-bit encryption** (value 537395200)
* **Policy**: `Network security: Minimum session security for NTLM SSP based (including secure RPC) servers` -> Set to **Require NTLMv2 session security, Require 128-bit encryption** (value 537395200)
* **Policy**: `Network access: Allow anonymous SID/Name translation` -> Set to **Disabled** (value 0)
* **Policy**: `Network security: Allow LocalSystem NULL session fallback` -> Set to **Disabled** (value 0)

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
1. Within the PAW GPO, navigate to:
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

Use this method to apply the settings locally (for testing or standalone PAW systems) or if the control is not manageable via standard GPO GUI interfaces.

[Download Script: Set-PAWAccountPolicies.ps1](implementation_scripts/Set-PAWAccountPolicies.ps1)

```powershell
# Set-PAWAccountPolicies.ps1
# Configures local account lockout, password parameters, smart card removal behavior, blank password blocks, Hello for Business, Microsoft accounts, secure channel options, and NTLM session security options on PAWs.

Write-Host "Applying PAW account and password policies..." -ForegroundColor Cyan

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
Set-ItemProperty -Path $LsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
Write-Host "[+] Blank password, NoLMHash, and client NTLMv2-only options enforced." -ForegroundColor Green

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

# 2. Enforce Account Lockout and Password Policy via secedit
$SecTempDir = Join-Path $env:TEMP "PAWAccountSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_account_sec.cfg"
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
    "LockoutBadCount"       = 5
    "ResetLockoutCount"     = 30
    "LockoutDuration"       = 30
    "ClearTextPassword"     = 0
    "MinimumPasswordLength" = 20
    "PasswordComplexity"    = 1
    "PasswordHistorySize"   = 24
    "MaxPasswordAge"        = 0
    "MinPasswordAge"        = 1
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

*To verify the settings have been applied:*

[Download Script: Test-PAWAccountPolicies.ps1](audit_scripts/Test-PAWAccountPolicies.ps1)

```powershell
# Test-PAWAccountPolicies.ps1
# Checks local registry and SecEdit settings for account lockout, password options, smart card removal behavior, PIN parameters, Hello for Business, Microsoft account settings, secure channel properties, and NTLM session configuration on PAWs.

Write-Host "--- Auditing PAW Account and Password Policies ---" -ForegroundColor Cyan

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
Test-RegistryValue $LsaPath "LmCompatibilityLevel" 5

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

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "PAWAccountAuditSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_account_audit.cfg"
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current database."
    return
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
$AccountSettings = @{
    "LockoutBadCount"       = 5
    "ResetLockoutCount"     = 30
    "LockoutDuration"       = 30
    "ClearTextPassword"     = 0
    "MinimumPasswordLength" = 20
    "PasswordComplexity"    = 1
    "PasswordHistorySize"   = 24
    "MaxPasswordAge"        = 0
    "MinPasswordAge"        = 1
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
* **ANSSI AD Hardening Guide**: Recommendations on password complexity, reversible encryption blocks, lockout management, and domain member secure channels.
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 2.3.7.3 (Accounts: Limit local account use of blank passwords...), Section 2.3.9.5 (Interactive logon: Smart card removal behavior), Section 2.3.10.2 (Microsoft network client: Send unencrypted password), Section 2.3.11.8 (Network access: Allow anonymous SID/Name translation), Section 2.3.11.10 (Network security: Allow LocalSystem NULL session fallback).
* **DoD Windows 11 Computer STIG v2r6**: Various account policy, PIN complexity, Windows Hello for Business, Microsoft account restrictions, WDigest disabled, and Netlogon secure channel parameters.
