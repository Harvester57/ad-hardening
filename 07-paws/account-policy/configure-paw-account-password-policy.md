# [REQ-PAW-152] Account Policy: Password Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Location / SecEdit Settings**:
    * `MinimumPasswordLength` = `20` (20 characters minimum)
    * `PasswordComplexity` = `1` (Complexity enabled)
    * `PasswordHistorySize` = `24` (24 passwords remembered)
    * `MaxPasswordAge` = `0` (Password does not expire / disabled)
    * `MinPasswordAge` = `1` (1 day minimum)
    * `ClearTextPassword` = `0` (Reversible encryption disabled)
    * `RelaxMinPasswordLengthLimits` = `1` (Relax minimum password length limits enabled)
    * `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning` = `14` (REG_DWORD, 14 days)

---

## Rationale
Enforcing a robust password baseline is critical on Privileged Access Workstations to prevent brute-force cracking, credential dictionary attacks, and unauthorized local password rotation:
* **Minimum Length (20 characters)**: Tier 0 administrative workstations require a minimum of 20 characters for local accounts (e.g. fallback local administrators). This length makes brute-force and offline GPU dictionary attacks mathematically unfeasible.
* **Complexity & Reversible Encryption**: Requiring character diversity while disabling reversible encryption ensures password hashes stored in the SAM or LSASS memory cannot be trivially decrypted.
* **Password History & Minimum Age**: Storing 24 passwords in history and requiring a 1-day minimum age prevents administrators from immediately cycling back to an old password.
* **No Expiration (MaxPasswordAge = 0)**: In accordance with NIST SP 800-63B and modern ANSSI guidelines, requiring periodic password changes is disabled for robust 20-character passwords, eliminating weak incremental patterns.

---

## Legacy Impact & Compatibility
* **Password Length**: Any administrative procedure that provisions local accounts must use passwords with at least 20 characters meeting complexity rules.
* **No Periodic Expiration**: While automatic password expiration is disabled, explicit password revocation and rotation procedures must remain in place for suspected credential leak events.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy`
4. Configure the settings:
   * **Enforce password history**: `24` passwords remembered
   * **Maximum password age**: `0` days (never expire)
   * **Minimum password age**: `1` day
   * **Minimum password length**: `20` characters
   * **Password must meet complexity requirements**: `Enabled`
   * **Store passwords using reversible encryption**: `Disabled`
   * **Relax minimum password length limits**: `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
   * **Interactive logon: Prompt user to change password before expiration**: `14` days

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountPasswordPolicy.ps1](../implementation_scripts/Configure-PawAccountPasswordPolicy.ps1)

```powershell
# Configure-PawAccountPasswordPolicy.ps1
Write-Host "Configuring PAW password policy..." -ForegroundColor Cyan

# 1. Configure PasswordExpiryWarning via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) { New-Item -Path $WinlogonPath -Force | Out-Null }
Set-ItemProperty -Path $WinlogonPath -Name "PasswordExpiryWarning" -Value 14 -Type DWord -Force

# 2. Configure SecEdit System Access password parameters
$SecTempDir = Join-Path $env:TEMP "PAWPasswordSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "paw_password.cfg"
$DbFile = Join-Path $SecTempDir "paw_password.sdb"
$LogFile = Join-Path $SecTempDir "paw_password.log"

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
Write-Host "PAW password policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountPasswordPolicyStatus.ps1](../audit_scripts/Get-PawAccountPasswordPolicyStatus.ps1)

```powershell
# Get-PawAccountPasswordPolicyStatus.ps1
Write-Host "--- Auditing PAW Password Policy ---" -ForegroundColor Cyan
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
$SecTempDir = Join-Path $env:TEMP "PAWPasswordAuditTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.1 (Password Policy), Section 2.3.7.8 (PasswordExpiryWarning)
* **ANSSI AD Hardening Guide**: Recommendations on local password complexity, length, and reversible encryption
* **DoD Windows 11 Computer STIG v2r6**: Password length and history rules
