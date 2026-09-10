# [REQ-END-163] Account Policy: Password Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy / Local Policies -> Security Options
* **Policy Settings**:
  * Enforce password history: `24` passwords remembered
  * Maximum password age: `0` days (never expire)
  * Minimum password age: `1` day
  * Minimum password length: `14` characters
  * Password must meet complexity requirements: `Enabled`
  * Store passwords using reversible encryption: `Disabled`
  * Relax minimum password length limits: `Enabled`
  * Interactive logon: Prompt user to change password before expiration: `14` days
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **SecEdit / Registry Parameters**:
  * `MinimumPasswordLength` = `14` (Characters required; relaxed boundary enabled)
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

Establishing a hardened password baseline across enterprise client workstations and member servers protects against password guessing, automated spray campaigns, and offline cryptanalysis:

### Technical Threat Vectors and Defense Mechanics
1. **Elevating Entropy via Length (`MinimumPasswordLength = 14`)**:
   In modern credential security, password length is the single most decisive factor determining resistance to offline cracking. Short 8-character passwords, even when complex, represent a keyspace of roughly `6.6 x 10^15` combinations, which high-end GPU rigs can exhaust rapidly. Elevating the minimum length to 14 characters expands the search space to over `4.6 x 10^27` combinations. Offline dictionary and brute-force cracking tools are rendered computationally infeasible against hashes of this length.
2. **Modern Expiration Guidance (`MaxPasswordAge = 0`)**:
   In compliance with NIST SP 800-63B, Microsoft Security Baselines, and ANSSI recommendations, periodic password resets (such as 60-day or 90-day cycles) are counterproductive. Frequent forced expirations prompt users to pick easily predictable modifications (e.g., changing `Spring2025!` to `Summer2025!`) or write passwords down. Coupling a strong 14-character minimum length with no expiration (`MaxPasswordAge = 0`) improves overall security by eliminating predictable patterns. Rapid credential rotation protocols remain reserved for events where account compromise is suspected.
3. **Disabling Reversible Encryption (`ClearTextPassword = 0`)**:
   Storing passwords using reversible encryption encrypts passwords using an algorithm whose key is known to the operating system. If an adversary gains access to the SAM database, they can reverse the encryption and retrieve plaintext passwords. Disabling reversible encryption ensures that only irreversible one-way cryptographic hashes are stored.
4. **Preventing Rapid Password Cycling (`PasswordHistorySize = 24`, `MinPasswordAge = 1`)**:
   Retaining a history of 24 passwords ensures users cannot reuse recent credentials. Pairing this with a 1-day minimum password age prevents users from immediately resetting their password 24 times consecutively to return to their original password.
5. **Enabling Relaxed Password Length Limits (`RelaxMinPasswordLengthLimits = 1`)**:
   Windows historically capped the GUI configuration of minimum password length at 14 characters. Enabling `RelaxMinPasswordLengthLimits` allows modern Windows systems to accept passphrases up to 128 characters without truncation or buffer issues.
6. **Endpoint vs PAW Comparison**:
   Standard Tier 2 endpoints enforce a 14-character minimum length to balance robust entropy with day-to-day business user experience. On Tier 0 PAWs, this threshold is tightened to 20 characters to provide extreme resistance for directory administrative accounts.

---

## Legacy Impact & Compatibility

* **End-User Password Updates**: When users next update their passwords, they will be required to provide a passphrase of at least 14 characters meeting complexity requirements. Organizations should train users on passphrase construction (e.g., combining 4 or 5 random words).
* **Legacy Service Accounts**: Hardcoded service accounts or third-party legacy applications with short password limitations must be identified and upgraded to support 14+ character passphrases or migrated to Group Managed Service Accounts (gMSAs).
* **LAPS for Local Administrators**: Local administrator accounts on member servers and workstations should be managed via Windows LAPS, configured to generate 14+ character randomized passwords automatically.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy or target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
4. Configure the following settings:
   * **Enforce password history**: Set to `24` passwords remembered
   * **Maximum password age**: Set to `0` days (never expire)
   * **Minimum password age**: Set to `1` day
   * **Minimum password length**: Set to `14` characters
   * **Password must meet complexity requirements**: Set to `Enabled`
   * **Store passwords using reversible encryption**: Set to `Disabled`
   * **Relax minimum password length limits**: Set to `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
6. Configure:
   * **Interactive logon: Prompt user to change password before expiration**: Set to `14` days
7. Link the GPO to the target Organizational Units and force replication.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountPasswordPolicy.ps1](../implementation_scripts/Configure-EndAccountPasswordPolicy.ps1)

```powershell
# Configure-EndAccountPasswordPolicy.ps1
# Description: Configures Endpoint password policy (14 char minimum, relaxed limits, no expiration) via SecEdit.

Write-Host "Configuring Endpoint password policy..." -ForegroundColor Cyan

# 1. Configure PasswordExpiryWarning via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
Set-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -Value 14 -Type DWord -Force

# 2. Configure SecEdit System Access password parameters
$SecTempDir = Join-Path $env:TEMP "EndpointPasswordSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "end_password.cfg"
$DbFile = Join-Path $SecTempDir "end_password.sdb"
$LogFile = Join-Path $SecTempDir "end_password.log"

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
    "MinimumPasswordLength"        = 14
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
Write-Host "Endpoint password policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountPasswordPolicyStatus.ps1](../audit_scripts/Get-EndAccountPasswordPolicyStatus.ps1)

```powershell
# Get-EndAccountPasswordPolicyStatus.ps1
# Description: Audits Endpoint password policy parameters via SecEdit and registry queries.

Write-Host "--- Auditing Endpoint Password Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Registry Setting
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
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
$SecTempDir = Join-Path $env:TEMP "EndpointPasswordAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
$CfgFile = Join-Path $SecTempDir "end_password_audit.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

$ExpectedSettings = @{
    "MinimumPasswordLength"        = 14
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
Confirm that `Minimum password length` indicates `14`, `Length of password history maintained` is `24`, and `Maximum password age (days)` indicates `Unlimited` (value `0`).

Verify the password expiration warning registry value:
```cmd
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v PasswordExpiryWarning
```
Confirm that `PasswordExpiryWarning` is set to `0xe` (Decimal `14`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 1.1.1 (Enforce password history >= 24), Section 1.1.2 (Maximum password age), Section 1.1.3 (Minimum password age >= 1), Section 1.1.4 (Minimum password length >= 14), Section 1.1.5 (Password complexity = Enabled), Section 1.1.6 (Relax minimum password length limits = Enabled), Section 1.1.7 (Reversible encryption = Disabled), Section 2.3.7.8 (PasswordExpiryWarning)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 1.1.1 through 1.1.7, Section 2.3.7.8
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 1.1.1 through 1.1.7, Section 2.3.7.8
* **DoD Windows 11 Computer STIG**: Rule SV-220703r879603_rule (Minimum password length), Rule SV-220704r879604_rule (Password complexity), Rule SV-220706r879606_rule (Password history)
* **NIST SP 800-63B**: Digital Identity Guidelines - Authentication and Lifecycle Management (Section 5.1.1.2 Memorized Secret Authenticators)
* **ANSSI Active Directory Hardening Guide**: Recommendations on password length, entropy, and disabling reversible encryption
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Password Policies
* **Related Controls**: [REQ-PAW-152: Account Policy: Password Policy for PAWs](../../07-paws/account-policy/configure-paw-account-password-policy.md), [REQ-END-164: Account Policy: Account Lockout Policy for Endpoints](configure-end-account-lockout-policy.md)
