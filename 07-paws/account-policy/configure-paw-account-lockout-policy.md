# [REQ-PAW-153] Account Policy: Account Lockout Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy / Local Policies -> Security Options
* **Policy Settings**:
  * Account lockout threshold: `5` invalid logon attempts
  * Reset account lockout counter after: `30` minutes
  * Account lockout duration: `30` minutes
  * Allow Administrator account lockout: `Enabled`
  * Interactive logon: Machine account lockout threshold: `10`
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **SecEdit / Registry Parameters**:
  * `LockoutBadCount` = `5` (Invalid logon attempts permitted before lockout)
  * `ResetLockoutCount` = `30` (Minutes before failed attempt counter resets)
  * `LockoutDuration` = `30` (Minutes an account remains locked out)
  * `AllowAdministratorLockout` = `1` (Applies lockout policy to the built-in Administrator account)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts` = `10` (REG_DWORD)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Rationale

Account lockout policies define the defensive response when incorrect credentials are submitted against user accounts. On Privileged Access Workstations, tight lockout thresholds protect administrative credentials from automated brute-force attacks and targeted dictionary probes:

### Technical Threat Vectors and Defense Mechanics
1. **Thwarting Targeted Brute-Force and Password Spraying (`LockoutBadCount = 5`)**:
   In a brute-force or password spraying campaign, attackers systematically test credential pairs against administrative accounts. Without an enforced lockout threshold, an adversary who establishes network connectivity can execute millions of online authentication requests without consequence. On PAWs, which manage Tier 0 directory infrastructure, the lockout threshold is tightened to 5 failed attempts (compared to 10 on standard endpoints). Because administrative staff authenticate using managed password managers, smart cards, or WHfB, accidental typing failures are minimal, making a 5-attempt threshold ideal for neutralizing rapid attack scripts.
2. **Observation Window and Lockout Duration (`ResetLockoutCount = 30`, `LockoutDuration = 30`)**:
   Setting both the reset counter window and the lockout duration to 30 minutes prevents automated tools from executing low-and-slow dictionary attacks. If an attacker attempts guesses spaced over short intervals, the counter accumulates and triggers a 30-minute lockout. This dramatically increases the time required to guess even a small set of passwords to months or years, while generating high-priority Security audit alerts (Event ID 4740).
3. **Built-in Administrator Protection (`AllowAdministratorLockout = 1`)**:
   Historically in Windows environments, the built-in Administrator account (RID 500) was immune to account lockout policies to prevent denial-of-service conditions. Attackers exploited this exception to target the built-in Administrator with infinite brute-force attacks across remote interfaces. Beginning with modern security baselines, enabling `AllowAdministratorLockout = 1` enforces the lockout threshold on the built-in Administrator account, eliminating this long-standing attack vector.
4. **Machine Account Lockout Threshold (`MaxDevicePasswordFailedAttempts = 10`)**:
   Configuring `MaxDevicePasswordFailedAttempts` bounds the maximum number of failed authentication attempts permitted directly at the interactive console of the device before the console locks. This mitigates physical access attacks and rapid PIN guessing on the local machine.
5. **Tier 0 PAW Posture**:
   Tighter lockout thresholds on PAWs reflect the high sensitivity of Tier 0 assets. Combined with smart card enforcement, these lockout controls protect fallback local administrator accounts and directory credentials from persistent guessing.

---

## Legacy Impact & Compatibility

* **Administrative Lockouts**: If an administrator mistypes their password 5 times within 30 minutes, their account will be locked for 30 minutes. To maintain operational resilience, organizations must have documented procedures for an alternate Tier 0 administrator to unlock accounts if urgent directory access is required.
* **Denial-of-Service Risk**: Malicious actors aware of administrative account names could deliberately enter incorrect passwords to cause administrative lockouts. This risk is mitigated by hiding usernames on the lock screen (`DontDisplayLastUserName = 1`), restricting network access to PAWs, and leveraging smart card authentication where password prompts are bypassed.
* **SecEdit Enforcement**: Account lockout parameters on domain-joined systems are typically managed by the Default Domain Policy; configuring these settings locally via security templates ensures that local SAM accounts and standalone evaluation baselines remain strictly hardened.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO linked to the PAW Organizational Unit (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
4. Configure the following settings:
   * **Account lockout threshold**: Set to `5` invalid logon attempts
   * **Reset account lockout counter after**: Set to `30` minutes
   * **Account lockout duration**: Set to `30` minutes
   * **Allow Administrator account lockout**: Set to `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
6. Configure:
   * **Interactive logon: Machine account lockout threshold**: Set to `10`
7. Link the GPO to the dedicated PAW OU and force update via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountLockoutPolicy.ps1](../implementation_scripts/Configure-PawAccountLockoutPolicy.ps1)

```powershell
# Configure-PawAccountLockoutPolicy.ps1
# Description: Configures account lockout parameters and Administrator lockout protection on PAWs via SecEdit.

Write-Host "Configuring PAW account lockout policy..." -ForegroundColor Cyan

# 1. Configure MaxDevicePasswordFailedAttempts via Registry
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPolicyPath)) {
    New-Item -Path $SystemPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Force

# 2. Configure SecEdit System Access lockout parameters
$SecTempDir = Join-Path $env:TEMP "PAWLockoutSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_lockout.cfg"
$DbFile = Join-Path $SecTempDir "paw_lockout.sdb"
$LogFile = Join-Path $SecTempDir "paw_lockout.log"

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

$LockoutSettings = @{
    "LockoutBadCount"           = 5
    "ResetLockoutCount"         = 30
    "LockoutDuration"           = 30
    "AllowAdministratorLockout" = 1
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
        foreach ($Key in $LockoutSettings.Keys) {
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
        foreach ($Key in $LockoutSettings.Keys) {
            $Val = $LockoutSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) {
    Throw "Failed to apply SecEdit lockout policy."
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PAW lockout policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountLockoutPolicyStatus.ps1](../audit_scripts/Get-PawAccountLockoutPolicyStatus.ps1)

```powershell
# Get-PawAccountLockoutPolicyStatus.ps1
# Description: Audits account lockout policy parameters on PAWs via SecEdit.

Write-Host "--- Auditing PAW Account Lockout Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Registry Setting
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$MaxDeviceVal = (Get-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -ErrorAction SilentlyContinue).MaxDevicePasswordFailedAttempts
if ($null -eq $MaxDeviceVal -or $MaxDeviceVal -gt 10 -or $MaxDeviceVal -eq 0) {
    Write-Host "    [!] VULNERABLE: MaxDevicePasswordFailedAttempts is set to '$MaxDeviceVal' (Expected: 10 or fewer, but not 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] MaxDevicePasswordFailedAttempts: $MaxDeviceVal (Secure)" -ForegroundColor Green
}

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "PAWLockoutAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
$CfgFile = Join-Path $SecTempDir "paw_lockout_audit.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

$ExpectedSettings = @{
    "LockoutBadCount"           = 5
    "ResetLockoutCount"         = 30
    "LockoutDuration"           = 30
    "AllowAdministratorLockout" = 1
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

Verify the applied account lockout policies using `net accounts`:
```cmd
net accounts
```
Verify that `Lockout threshold` shows `5`, `Lockout duration (minutes)` shows `30`, and `Lockout observation window (minutes)` shows `30`.

Verify the machine account lockout threshold registry value:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MaxDevicePasswordFailedAttempts
```
Confirm that `MaxDevicePasswordFailedAttempts` is set to `0xa` (Decimal `10`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 1.2.1 (Account lockout duration >= 15 minutes), Section 1.2.2 (Account lockout threshold <= 10 attempts), Section 1.2.3 (AllowAdministratorLockout = Enabled), Section 1.2.4 (Reset account lockout counter >= 15 minutes), Section 2.3.7.4 (MaxDevicePasswordFailedAttempts <= 10)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 1.2.1, Section 1.2.2, Section 1.2.3, Section 1.2.4, Section 2.3.7.4
* **DoD Windows 11 Computer STIG**: Rule SV-220700r879600_rule (Account lockout duration), Rule SV-220701r879601_rule (Account lockout threshold), Rule SV-220702r879602_rule (Account lockout observation window)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Account Lockout Thresholds and Brute-Force Throttling)
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Account Lockout Policies
* **Related Controls**: [REQ-END-164: Account Policy: Account Lockout Policy for Endpoints](../../08-endpoints/account-policy/configure-end-account-lockout-policy.md), [REQ-PAW-152: Account Policy: Password Policy for PAWs](configure-paw-account-password-policy.md)
