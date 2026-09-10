# [REQ-PAW-152] Account Policy: Password Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy / Local Policies -> Security Options
* **Policy Settings**:
  * Enforce password history: `24` passwords remembered
  * Maximum password age: `0` days (never expire)
  * Minimum password age: `1` day
  * Minimum password length: `20` characters
  * Password must meet complexity requirements: `Enabled`
  * Store passwords using reversible encryption: `Disabled`
  * Relax minimum password length limits: `Enabled`
  * Interactive logon: Prompt user to change password before expiration: `14` days
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **SecEdit / Registry Parameters**:
  * `MinimumPasswordLength` = `20` (Characters required; relaxed boundary enabled)
  * `PasswordComplexity` = `1` (Requires uppercase, lowercase, numbers, and symbols)
  * `PasswordHistorySize` = `24` (Distinct past passwords retained)
  * `MaxPasswordAge` = `0` (Zero days = expiration disabled per NIST SP 800-63B)
  * `MinPasswordAge` = `1` (Days before a user can change their password again)
  * `ClearTextPassword` = `0` (Reversible encryption prohibited)
  * `RelaxMinPasswordLengthLimits` = `1` (Allows password lengths exceeding 14 characters, up to 128)
  * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning` = `14` (REG_DWORD)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.002: Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Rationale

Privileged Access Workstations host the credential material and management tools responsible for enterprise directory survival. While interactive logons on PAWs mandate hardware-backed multi-factor authentication (smart cards / WHfB), local fallback accounts (such as the local Administrator managed by Windows LAPS) must enforce an impervious password baseline to resist offline cryptanalysis:

### Technical Threat Vectors and Defense Mechanics
1. **Mathematical Resistance to Offline Cracking (`MinimumPasswordLength = 20`)**:
   Modern GPU clusters (e.g., arrays of NVIDIA RTX 4090s or dedicated hash-cracking hardware) compute tens of billions of NTLM or SHA-1 hashes per second. An 8-character password has approximately `6.6 x 10^15` combinations and can be completely exhausted in hours. Expanding the minimum length to 20 characters across the full printable character set expands the keyspace to over `10^39` combinations. At this entropy level, brute-force search and dictionary permutation attacks become mathematically impossible within any meaningful timeframe.
2. **Unlocking Extended Length Limits (`RelaxMinPasswordLengthLimits = 1`)**:
   Historically, the Windows Group Policy Editor and SAM engine capped the configurable `MinimumPasswordLength` setting at 14 characters due to legacy LAN Manager data structures. Beginning with modern updates, Microsoft introduced `RelaxMinPasswordLengthLimits = 1`, permitting administrators to configure password length policies up to 128 characters. Enabling this setting allows the 20-character PAW baseline to be enforced seamlessly.
3. **Prohibiting Reversible Encryption (`ClearTextPassword = 0`)**:
   The "Store passwords using reversible encryption" setting stores password hashes encrypted with a reversible RC4 algorithm whose key material is accessible to LSA and domain controllers. In practice, reversible encryption is identical to storing plaintext passwords on disk. If an attacker extracts the SAM or directory database, they can decrypt all passwords instantly. Disabling reversible encryption is an absolute requirement.
4. **Modern Expiration Philosophy (`MaxPasswordAge = 0`)**:
   In accordance with NIST Special Publication 800-63B and modern ANSSI guidance, arbitrary periodic password expiration (e.g., mandatory resets every 60 or 90 days) degrades security. When forced to change passwords frequently, users predictably increment numbers or append seasons (e.g., `Summer2025! -> Autumn2025!`), reducing actual entropy. Combining an uncompromising 20-character minimum length with no expiration (`MaxPasswordAge = 0`) maximizes password quality, while immediate revocation protocols are triggered upon any suspected credential compromise.
5. **Preventing Password Cycling (`PasswordHistorySize = 24`, `MinPasswordAge = 1`)**:
   Retaining a history of 24 passwords alongside a 1-day minimum password age prevents administrators from immediately rotating through multiple dummy passwords in a single session to return to a favored credential.
6. **Tier 0 PAW Baseline Comparison**:
   Standard Tier 2 endpoints enforce a 14-character minimum length. On Tier 0 PAWs, the threshold is elevated to 20 characters, reflecting the tier's role as the root of directory trust.

---

## Legacy Impact & Compatibility

* **Local Account Management via Windows LAPS**: All local administrator accounts on PAWs must be managed by Windows LAPS (Local Administrator Password Solution) configured to generate 20+ character passwords with full complexity.
* **Manual Password Changes**: Any manual password reset for fallback local accounts must satisfy the 20-character complexity requirements or the SAM engine will reject the change.
* **Pre-requisites**: Workstation OS must support relaxed password length limits (Windows 10 version 2004+ or earlier versions with the relevant cumulative update).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
4. Configure the following settings:
   * **Enforce password history**: Set to `24` passwords remembered
   * **Maximum password age**: Set to `0` days (never expire)
   * **Minimum password age**: Set to `1` day
   * **Minimum password length**: Set to `20` characters
   * **Password must meet complexity requirements**: Set to `Enabled`
   * **Store passwords using reversible encryption**: Set to `Disabled`
   * **Relax minimum password length limits**: Set to `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
6. Configure:
   * **Interactive logon: Prompt user to change password before expiration**: Set to `14` days
7. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountPasswordPolicy.ps1](../implementation_scripts/Configure-PawAccountPasswordPolicy.ps1)

```powershell
# Configure-PawAccountPasswordPolicy.ps1
# Description: Configures PAW password policy (20 char minimum, relaxed limits, no expiration) via SecEdit.

Write-Host "Configuring PAW password policy..." -ForegroundColor Cyan

# 1. Configure PasswordExpiryWarning via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -Value 14 -Type DWord -Force

# 2. Configure SecEdit System Access password parameters
$SecTempDir = Join-Path $env:TEMP "PAWPasswordSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_password.cfg"
$DbFile = Join-Path $SecTempDir "paw_password.sdb"
$LogFile = Join-Path $SecTempDir "paw_password.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Throw "Failed to export current security template."
}

$ConfigText = Get-Content -Path $CfgFile -Raw
if ($ConfigText -notmatch "\[System Access\]") {
    $ConfigText += "`r`n[System Access]`r`n"
}

$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InSystemAccess = $false

$PwdSettings = @{
    "MinimumPasswordLength"        = 20
    "PasswordComplexity"           = 1
    "PasswordHistorySize"          = 24
    "MaxPasswordAge"               = 0
    "MinPasswordAge"               = 1
    "ClearTextPassword"            = 0
    "RelaxMinPasswordLengthLimits" = 1
}

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        if ($Matches[1] -eq "System Access") {
            $InSystemAccess = $true
        } else {
            $InSystemAccess = $false
        }
    }
    if ($InSystemAccess) {
        $IsManaged = $false
        foreach ($Key in $PwdSettings.Keys) {
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

$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[System Access]") {
        foreach ($Key in $PwdSettings.Keys) {
            $Val = $PwdSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) {
    Throw "Failed to apply SecEdit password policy."
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PAW password policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountPasswordPolicyStatus.ps1](../audit_scripts/Get-PawAccountPasswordPolicyStatus.ps1)

```powershell
# Get-PawAccountPasswordPolicyStatus.ps1
# Description: Audits PAW password policy parameters via SecEdit and registry queries.

Write-Host "--- Auditing PAW Password Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Registry Setting
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path -Path $WinlogonPath)) {
    Write-Host "    [!] MISSING KEY: $WinlogonPath" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    $WarnVal = (Get-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -ErrorAction SilentlyContinue).PasswordExpiryWarning
    if ($null -eq $WarnVal -or $WarnVal -lt 5 -or $WarnVal -gt 14) {
        Write-Host "    [!] VULNERABLE: PasswordExpiryWarning is set to '$WarnVal' (Expected: 5-14)" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] PasswordExpiryWarning: $WarnVal (Secure)" -ForegroundColor Green
    }
}

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "PAWPasswordAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
$CfgFile = Join-Path $SecTempDir "paw_password_audit.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

$ExpectedSettings = @{
    "MinimumPasswordLength"        = 20
    "PasswordComplexity"           = 1
    "PasswordHistorySize"          = 24
    "MaxPasswordAge"               = 0
    "MinPasswordAge"               = 1
    "ClearTextPassword"            = 0
    "RelaxMinPasswordLengthLimits" = 1
}

foreach ($Key in $ExpectedSettings.Keys) {
    $Expected = $ExpectedSettings[$Key]
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    if ($Actual -ne [string]$Expected) {
        Write-Host "    [!] VULNERABLE: $($Key) = '$Actual' (Expected: '$Expected')" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Key): $Actual (Secure)" -ForegroundColor Green
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

Verify the active local password policy settings using `net accounts`:
```cmd
net accounts
```
Verify that `Minimum password length` reflects `20`, `Length of password history maintained` is `24`, and `Maximum password age (days)` indicates `Unlimited` (value `0`).

Verify the password expiration warning registry value:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v PasswordExpiryWarning
```
Confirm that `PasswordExpiryWarning` is set to `0xe` (Decimal `14`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 1.1.1 (Enforce password history >= 24), Section 1.1.2 (Maximum password age), Section 1.1.3 (Minimum password age >= 1), Section 1.1.4 (Minimum password length >= 14), Section 1.1.5 (Password complexity = Enabled), Section 1.1.6 (Relax minimum password length limits = Enabled), Section 1.1.7 (Reversible encryption = Disabled), Section 2.3.7.8 (PasswordExpiryWarning)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 1.1.1 through 1.1.7, Section 2.3.7.8
* **DoD Windows 11 Computer STIG**: Rule SV-220703r879603_rule (Minimum password length), Rule SV-220704r879604_rule (Password complexity), Rule SV-220706r879606_rule (Password history)
* **NIST SP 800-63B**: Digital Identity Guidelines - Authentication and Lifecycle Management (Section 5.1.1.2 Memorized Secret Authenticators)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Tier 0 Password Policies and Entropy Enforcement)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Password Policies
* **Related Controls**: [REQ-END-163: Account Policy: Password Policy for Endpoints](../../08-endpoints/account-policy/configure-end-account-password-policy.md), [REQ-PAW-153: Account Policy: Account Lockout Policy for PAWs](configure-paw-account-lockout-policy.md)
