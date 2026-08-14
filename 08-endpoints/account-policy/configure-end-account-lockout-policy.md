# [REQ-END-164] Account Policy: Account Lockout Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Location / SecEdit Settings**:
    * `LockoutBadCount` = `10` (10 invalid logon attempts allowed)
    * `ResetLockoutCount` = `15` (15 minutes lockout observation window)
    * `LockoutDuration` = `15` (15 minutes lockout duration)
    * `AllowAdministratorLockout` = `1` (Allow Administrator account lockout enabled)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts` = `10` (REG_DWORD)

---

## Rationale
Configuring account lockout parameters mitigates automated brute-force attacks and password spraying attempts against domain and local user accounts:
* **Lockout Threshold (10 attempts)**: Restricting invalid logon attempts to 10 limits password guessing while avoiding excessive helpdesk lockout tickets for legitimate users who forget their passwords.
* **Duration & Observation Window (15 minutes)**: Setting lockout duration and reset windows to 15 minutes restricts sustained automated password guessing.
* **Administrator Lockout**: Enabling Administrator account lockout prevents attackers from evading lockout protection by targeting the built-in Administrator account.

---

## Legacy Impact & Compatibility
* **User Lockouts**: Users mistyping credentials more than 10 times will be temporarily locked out for 15 minutes before the counter resets.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy or Endpoints GPO.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
4. Configure the settings:
   * **Account lockout threshold**: `10` invalid logon attempts
   * **Reset account lockout counter after**: `15` minutes
   * **Account lockout duration**: `15` minutes
   * **Allow Administrator account lockout**: `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
   * **Interactive logon: Machine account lockout threshold**: `10`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountLockoutPolicy.ps1](../implementation_scripts/Configure-EndAccountLockoutPolicy.ps1)

```powershell
# Configure-EndAccountLockoutPolicy.ps1
Write-Host "Configuring Endpoint account lockout policy..." -ForegroundColor Cyan

# 1. Configure MaxDevicePasswordFailedAttempts via Registry
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPolicyPath)) { New-Item -Path $SystemPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Force

# 2. Configure SecEdit System Access lockout parameters
$SecTempDir = Join-Path $env:TEMP "EndLockoutSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "end_lockout.cfg"
$DbFile = Join-Path $SecTempDir "end_lockout.sdb"
$LogFile = Join-Path $SecTempDir "end_lockout.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) { Throw "Failed to export current security template." }

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
        if ($Matches[1] -eq "System Access") { $InSystemAccess = $true } else { $InSystemAccess = $false }
    }
    if ($InSystemAccess) {
        $IsManaged = $false
        foreach ($Key in $LockoutSettings.Keys) {
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
        foreach ($Key in $LockoutSettings.Keys) {
            $Val = $LockoutSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to apply SecEdit lockout policy." }

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Endpoint lockout policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountLockoutPolicyStatus.ps1](../audit_scripts/Get-EndAccountLockoutPolicyStatus.ps1)

```powershell
# Get-EndAccountLockoutPolicyStatus.ps1
Write-Host "--- Auditing Endpoint Account Lockout Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

# 1. Audit Registry Setting
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$MaxDeviceVal = (Get-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -ErrorAction SilentlyContinue).MaxDevicePasswordFailedAttempts
if ($null -eq $MaxDeviceVal -or $MaxDeviceVal -gt 10 -or $MaxDeviceVal -eq 0) {
    Write-Host "    [!] VULNERABLE: MaxDevicePasswordFailedAttempts is set to '$MaxDeviceVal' (Expected: 10 or fewer, but not 0)" -ForegroundColor Red
    $script:Vulnerable = $true
} else {
    Write-Host "    [+] MaxDevicePasswordFailedAttempts: $MaxDeviceVal" -ForegroundColor Green
}

# 2. Audit SecEdit Settings
$SecTempDir = Join-Path $env:TEMP "EndLockoutAuditTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
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
* **CIS Microsoft Windows 10/11 Benchmark**: Section 1.2 (Account Lockout Policy), Section 1.2.3 (AllowAdministratorLockout), Section 2.3.7.4 (MaxDevicePasswordFailedAttempts)
* **ANSSI AD Hardening Guide**: Recommendations on account lockout management
* **DoD Windows 11 Computer STIG v2r6**: Account lockout threshold and observation window rules
