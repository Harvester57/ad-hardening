# [REQ-END-164] Account Policy: Account Lockout Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Account Lockout Policy / Local Policies -> Security Options
* **Policy Settings**:
  * Account lockout threshold: `10` invalid logon attempts
  * Reset account lockout counter after: `15` minutes
  * Account lockout duration: `15` minutes
  * Allow Administrator account lockout: `Enabled`
  * Interactive logon: Machine account lockout threshold: `10`
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
* **SecEdit / Registry Parameters**:
  * `LockoutBadCount` = `10` (Invalid logon attempts permitted before lockout)
  * `ResetLockoutCount` = `15` (Minutes before failed attempt counter resets)
  * `LockoutDuration` = `15` (Minutes an account remains locked out)
  * `AllowAdministratorLockout` = `1` (Applies lockout policy to the built-in Administrator account)
  * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts` = `10` (REG_DWORD)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1110.001: Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/), [T1110.003: Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)

---

## Rationale

Configuring a balanced, resilient account lockout baseline across enterprise client workstations and member servers defends against automated password guessing and password spraying while minimizing business interruption from user typos:

### Technical Threat Vectors and Defense Mechanics
1. **Mitigating Online Password Guessing (`LockoutBadCount = 10`)**:
   Without an account lockout policy, adversaries can use automated authentication scripts (such as Hydra, Medusa, or CME) to execute high-speed dictionary attacks against network services (SMB, RDP, WinRM). Configuring a threshold of 10 failed logon attempts halts automated attacks after a negligible number of attempts, rendering exhaustive dictionary attacks ineffective. A 10-attempt threshold accommodates occasional user typing errors while providing robust resistance to automated attack tools.
2. **Observation Window and Temporary Lockout Duration (`ResetLockoutCount = 15`, `LockoutDuration = 15`)**:
   Setting both the lockout reset counter and the duration window to 15 minutes forces attackers into prolonged delays between guessing attempts. Attempting a modest list of 1,000 passwords would require over 24 hours of sustained execution, creating a clear audit trail in the Windows Security event log (Event ID 4625 for failed logons, Event ID 4740 for account lockouts) that alerts the Security Operations Center (SOC).
3. **Closing the Built-in Administrator Loophole (`AllowAdministratorLockout = 1`)**:
   In legacy Windows architecture, the built-in Administrator account (RID 500) was exempt from account lockout policies to prevent administrators from locking themselves out of standalone systems. Attackers routinely targeted this account with infinite online brute-force attacks across network interfaces. Enabling `AllowAdministratorLockout = 1` extends lockout enforcement to the built-in Administrator account, closing this high-risk attack pathway.
4. **Interactive Machine Lockout Control (`MaxDevicePasswordFailedAttempts = 10`)**:
   Setting `MaxDevicePasswordFailedAttempts` ensures that the local physical console locks after 10 consecutive failed interactive logons, thwarting rapid manual or hardware-assisted keyboard guessing attacks on unattended workstations.
5. **Endpoint vs PAW Threshold Differences**:
   Standard Tier 2 endpoints balance security with user usability by utilizing a 10-attempt threshold and a 15-minute lockout window. In contrast, Tier 0 PAWs enforce a tighter 5-attempt threshold and a 30-minute lockout window due to the extreme sensitivity of administrative directory accounts.

---

## Legacy Impact & Compatibility

* **End-User Lockouts**: Users who inadvertently enter an incorrect password 10 times will be locked out for 15 minutes. The account will automatically unlock after 15 minutes without requiring helpdesk intervention, provided the user stops submitting incorrect passwords.
* **Denial-of-Service Considerations**: Malicious actors could attempt to lock out known user accounts by submitting false credentials. Hiding usernames on the lock screen (`DontDisplayLastUserName = 1`) and deploying multi-factor authentication (WHfB) mitigates this risk.
* **Domain vs Local Scope**: On domain members, domain account lockouts are processed by Domain Controllers via the Default Domain Policy; configuring this setting locally via security templates ensures local SAM accounts and non-domain evaluation baselines remain hardened.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy or the GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
4. Configure the following settings:
   * **Account lockout threshold**: Set to `10` invalid logon attempts
   * **Reset account lockout counter after**: Set to `15` minutes
   * **Account lockout duration**: Set to `15` minutes
   * **Allow Administrator account lockout**: Set to `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
6. Configure:
   * **Interactive logon: Machine account lockout threshold**: Set to `10`
7. Link the GPO to the appropriate workstation and server Organizational Units.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountLockoutPolicy.ps1](../implementation_scripts/Configure-EndAccountLockoutPolicy.ps1)

```powershell
# Configure-EndAccountLockoutPolicy.ps1
# Description: Configures account lockout parameters and Administrator lockout protection on Endpoints via SecEdit.

Write-Host "Configuring Endpoint account lockout policy..." -ForegroundColor Cyan

# 1. Configure MaxDevicePasswordFailedAttempts via Registry
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPolicyPath)) {
    New-Item -Path $SystemPolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Force

# 2. Configure SecEdit System Access lockout parameters
$SecTempDir = Join-Path $env:TEMP "EndpointLockoutSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "end_lockout.cfg"
$DbFile = Join-Path $SecTempDir "end_lockout.sdb"
$LogFile = Join-Path $SecTempDir "end_lockout.log"

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
    "LockoutBadCount"           = 10
    "ResetLockoutCount"         = 15
    "LockoutDuration"           = 15
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
Write-Host "Endpoint lockout policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountLockoutPolicyStatus.ps1](../audit_scripts/Get-EndAccountLockoutPolicyStatus.ps1)

```powershell
# Get-EndAccountLockoutPolicyStatus.ps1
# Description: Audits account lockout policy parameters on Endpoints via SecEdit.

Write-Host "--- Auditing Endpoint Account Lockout Policy ---" -ForegroundColor Cyan
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
$SecTempDir = Join-Path $env:TEMP "EndpointLockoutAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
$CfgFile = Join-Path $SecTempDir "end_lockout_audit.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

$ExpectedSettings = @{
    "LockoutBadCount"           = 10
    "ResetLockoutCount"         = 15
    "LockoutDuration"           = 15
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
Confirm that `Lockout threshold` indicates `10`, `Lockout duration (minutes)` is `15`, and `Lockout observation window (minutes)` is `15`.

Verify the machine account lockout threshold registry value:
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v MaxDevicePasswordFailedAttempts
```
Confirm that `MaxDevicePasswordFailedAttempts` returns `0xa` (Decimal `10`).

---

## Sources & Compliance References
* **CIS Microsoft Windows 10 Enterprise Benchmark**: Section 1.2.1 (Account lockout duration >= 15 minutes), Section 1.2.2 (Account lockout threshold <= 10 attempts), Section 1.2.3 (AllowAdministratorLockout = Enabled), Section 1.2.4 (Reset account lockout counter >= 15 minutes), Section 2.3.7.4 (MaxDevicePasswordFailedAttempts <= 10)
* **CIS Microsoft Windows 11 Enterprise Benchmark**: Section 1.2.1, Section 1.2.2, Section 1.2.3, Section 1.2.4, Section 2.3.7.4
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 1.2.1, Section 1.2.2, Section 1.2.3, Section 1.2.4, Section 2.3.7.4
* **DoD Windows 11 Computer STIG**: Rule SV-220700r879600_rule (Account lockout duration), Rule SV-220701r879601_rule (Account lockout threshold), Rule SV-220702r879602_rule (Account lockout observation window)
* **ANSSI Active Directory Hardening Guide**: Recommendations on account lockout management and password spraying mitigation
* **Microsoft Security Baseline Focus**: Windows Client Security Baseline - Account Lockout Policies
* **Related Controls**: [REQ-PAW-153: Account Policy: Account Lockout Policy for PAWs](../../07-paws/account-policy/configure-paw-account-lockout-policy.md), [REQ-END-163: Account Policy: Password Policy for Endpoints](configure-end-account-password-policy.md)
