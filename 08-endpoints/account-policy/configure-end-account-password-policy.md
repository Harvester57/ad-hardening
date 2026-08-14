# [REQ-END-163] Account Policy: Password Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Location / SecEdit Settings**:
    * `MinimumPasswordLength` = `14` (14 characters minimum)
    * `PasswordComplexity` = `1` (Complexity enabled)
    * `PasswordHistorySize` = `24` (24 passwords remembered)
    * `MaxPasswordAge` = `0` (Password does not expire / disabled)
    * `MinPasswordAge` = `1` (1 day minimum)
    * `ClearTextPassword` = `0` (Reversible encryption disabled)
    * `RelaxMinPasswordLengthLimits` = `1` (Relax minimum password length limits enabled)
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning` = `14` (REG_DWORD, 14 days)

---

## Rationale
Enforcing a comprehensive password policy across enterprise endpoints establishes a fundamental defense against password spraying, dictionary attacks, and offline hash cracking:
* **Minimum Length (14 characters)**: In alignment with ANSSI and CIS benchmarks for standard endpoints, a 14-character minimum length significantly raises entropy and computational resistance against brute-force attacks.
* **Complexity & Reversible Encryption**: Requiring character variety while disabling reversible encryption ensures password hashes stored in SAM or directory databases cannot be decrypted.
* **Password History & Minimum Age**: Mandating a 24-password history and 1-day minimum age prevents users from cycling between predictable password variations.
* **No Expiration (MaxPasswordAge = 0)**: In accordance with NIST SP 800-63B and modern ANSSI guidelines, periodic password changes are disabled for robust 14-character passwords, stopping weak incremental modifications.

---

## Legacy Impact & Compatibility
* **Password Length**: Users with passwords shorter than 14 characters must choose a compliant password during their next update. Service accounts or legacy tools with hardcoded short credentials must be modernized.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy or Endpoints GPO.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
4. Configure the settings:
   * **Enforce password history**: `24` passwords remembered
   * **Maximum password age**: `0` days (never expire)
   * **Minimum password age**: `1` day
   * **Minimum password length**: `14` characters
   * **Password must meet complexity requirements**: `Enabled`
   * **Store passwords using reversible encryption**: `Disabled`
   * **Relax minimum password length limits**: `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
   * **Interactive logon: Prompt user to change password before expiration**: `14` days

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountPasswordPolicy.ps1](../implementation_scripts/Configure-EndAccountPasswordPolicy.ps1)

```powershell
# Configure-EndAccountPasswordPolicy.ps1
Write-Host "Configuring Endpoint password policy..." -ForegroundColor Cyan

# 1. Configure PasswordExpiryWarning via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -Value 14 -Type DWord -Force

# 2. Configure SecEdit System Access password parameters
$SecTempDir = Join-Path $env:TEMP "EndPasswordSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "end_password.cfg"
$DbFile = Join-Path $SecTempDir "end_password.sdb"
$LogFile = Join-Path $SecTempDir "end_password.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) { Throw "Failed to export current security template." }

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
        if ($Matches[1] -eq "System Access") { $InSystemAccess = $true } else { $InSystemAccess = $false }
    }
    if ($InSystemAccess) {
        $IsManaged = $false
        foreach ($Key in $PwdSettings.Keys) {
            if ($Line -match "^\s*$($Key)\s*=") { $IsManaged = $true; break }
        }
        if (-not $IsManaged) { $NewLines += $Line }
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
if ($Proc.ExitCode -ne 0) { Throw "Failed to apply SecEdit password policy." }

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Endpoint password policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountPasswordPolicyStatus.ps1](../audit_scripts/Get-EndAccountPasswordPolicyStatus.ps1)

```powershell
# Get-EndAccountPasswordPolicyStatus.ps1
Write-Host "--- Auditing Endpoint Password Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Registry Setting
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$WarnVal = (Get-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -ErrorAction SilentlyContinue).PasswordExpiryWarning
if ($WarnVal -lt 5 -or $WarnVal -gt 14) {
    Write-Host "    [!] VULNERABLE: PasswordExpiryWarning is set to '$WarnVal' (Expected: 5-14)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] PasswordExpiryWarning: $WarnVal" -ForegroundColor Green
}

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "EndPasswordAuditTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
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
        Write-Host "    [+] $($Key): $Actual" -ForegroundColor Green
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

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.1 (Password Policy), Section 1.1.6 (RelaxMinPasswordLengthLimits), Section 2.3.7.8 (PasswordExpiryWarning)
* **ANSSI AD Hardening Guide**: Recommendations on password length, complexity, and reversible encryption
* **DoD Windows 11 Computer STIG v2r6**: Password length and history parameters
