# Hardening Requirement: Configure Account and Password Policies

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **GPO Paths / Registry Locations**:
  * **GPO Paths**:
    * Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy
    * Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy
    * Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options
  * **Registry Locations**:
    * Configured via GptTmpl.inf (SecEdit System Access settings)
    * HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
      * `ScRemoveOption` = `"1"` (REG_SZ, 1 = Lock Workstation)
    * HKLM\System\CurrentControlSet\Control\Lsa
      * `LimitBlankPasswordUse` = `1` (REG_DWORD)

---

## Rationale
Securing authentication parameters and account controls reduces the risk of password attacks and session hijackings:

1. **Account Lockout Threshold (`LockoutBadCount`)**: Brute-force and password-spraying attacks target user accounts to discover credentials. If no lockout threshold is configured, an attacker can make infinite password attempts. Configuring a lockout threshold of 10 bad attempts mitigates online brute-force attacks.
2. **Account Lockout Reset (`ResetLockoutCount`)**: This policy dictates how long the failed logon counter persists before resetting. Setting this to 15 minutes ensures that password attempts are restricted over time without introducing major helpdesk overhead.
3. **Reversible Encryption (`ClearTextPassword`)**: Storing passwords using reversible encryption is equivalent to storing cleartext passwords in the directory database. This key option exists only for legacy application support (such as CHAP authentication) and must be disabled to prevent database dumping/credential recovery.
4. **Smart Card Removal Behavior (`ScRemoveOption`)**: In secure environments using Smart Card or token-based authentication, removing the card must automatically lock the desktop session (`1`). If disabled, a user leaving their workstation with the card removed leaves the session exposed.
5. **Blank Passwords Limit (`LimitBlankPasswordUse`)**: Restricting the use of blank passwords to physical console logons prevents attackers from using empty-password accounts to authenticate remotely over network shares or RDP.

---

## Legacy Impact & Compatibility
* **Account Lockouts**: Legitimate users who forget their passwords may lock themselves out. Standard procedures must exist for administrative reset of locked accounts.
* **Smart Card Removal**: Users must be trained to carry their smart cards with them, which automatically locks the session. Re-authenticating requires inserting the card and entering the PIN.
* **Reversible Encryption**: Disabling reversible encryption may break legacy applications that rely on reading cleartext password equivalents. These applications should be modernized to support modern Kerberos or SAML/OIDC federations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

#### Step 1: Configure Lockout and Password Policies (Domain-wide)
These settings must be configured in the **Default Domain Policy** or a GPO linked to the Domain root to apply domain-wide:
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the **Default Domain Policy**.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies`
4. Configure the settings:
   * **Account Lockout Policy**:
     * **Account lockout threshold**: `10` invalid logon attempts
     * **Reset account lockout counter after**: `15` minutes
     * **Account lockout duration**: `15` minutes (Must be greater than or equal to reset time)
   * **Password Policy**:
     * **Store passwords using reversible encryption**: `Disabled`

#### Step 2: Configure Local Security Options
In the endpoints GPO (e.g., `GPO_Hardening_Workstations`), navigate to:
`Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
* **Policy**: `Interactive logon: Smart card removal behavior` -> Set to **Lock Workstation** (value 1)
* **Policy**: `Accounts: Limit local account use of blank passwords to console logon only` -> Set to **Enabled** (value 1)

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Enforce the local security settings and SecEdit configuration locally.

```powershell
# Set-AccountPolicies.ps1
# Description: Configures local account lockout, password parameters (via secedit), smart card behavior, and blank password blocks.

Write-Host "Applying account and password policies..." -ForegroundColor Cyan

# 1. Enforce local security options via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
# ScRemoveOption: "1" = Lock Workstation, "2" = Force Logoff
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String
Write-Host "[+] Smart card removal behavior set to Lock Workstation." -ForegroundColor Green

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
Write-Host "[+] Blank password restriction enforced." -ForegroundColor Green

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
    "LockoutBadCount"     = 10
    "ResetLockoutCount"   = 15
    "LockoutDuration"     = 15
    "ClearTextPassword"   = 0
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
```powershell
# Test-AccountPolicies.ps1
# Description: Checks the local registry and SecEdit settings for account lockout, password options, and smart card removal behavior.

Write-Host "--- Auditing Account and Password Policies ---" -ForegroundColor Cyan

# 1. Audit Registry Settings
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$ScRemove = Get-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -ErrorAction SilentlyContinue
$ScRemoveVal = if ($ScRemove) { $ScRemove.ScRemoveOption } else { "" }
$ScRemoveColor = if ($ScRemoveVal -eq "1") { "Green" } else { "Red" }
Write-Host "    - Smart Card Removal Behavior: '$ScRemoveVal' (Required = '1' [Lock])" -ForegroundColor $ScRemoveColor

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
$BlankPwd = Get-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
$BlankPwdVal = if ($BlankPwd) { $BlankPwd.LimitBlankPasswordUse } else { 0 }
$BlankPwdColor = if ($BlankPwdVal -eq 1) { "Green" } else { "Red" }
Write-Host "    - Limit Blank Password Use: $BlankPwdVal (Required = 1)" -ForegroundColor $BlankPwdColor

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
    "LockoutBadCount"     = 10
    "ResetLockoutCount"   = 15
    "LockoutDuration"     = 15
    "ClearTextPassword"   = 0
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
    }
    Write-Host "    - System Access Setting: $($Key) | Actual: '$($Actual)' (Expected: '$($Expected)')" -ForegroundColor $Color
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.1 (Password Policy), Section 1.2 (Account Lockout Policy), Section 2.3.7.3 (Accounts: Limit local account use of blank passwords...), Section 2.3.9.5 (Interactive logon: Smart card removal behavior)
* **ANSSI AD Hardening Guide**: Recommendations on password complexity, reversible encryption blocks, and lockout management
