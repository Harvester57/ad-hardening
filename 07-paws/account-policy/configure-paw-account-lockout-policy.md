# [REQ-PAW-153] Account Policy: Account Lockout Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) (Tier 0 Workstations)
* **Operating Systems**: Windows 10/11 Enterprise

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
  * **Registry Location / SecEdit Settings**:
    * `LockoutBadCount` = `5` (5 invalid logon attempts allowed)
    * `ResetLockoutCount` = `30` (30 minutes lockout observation window)
    * `LockoutDuration` = `30` (30 minutes lockout duration)
    * `AllowAdministratorLockout` = `1` (Allow Administrator account lockout enabled)
    * `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts` = `10` (REG_DWORD)

---

## Rationale
Configuring strict account lockout parameters on Tier 0 administrative workstations protects high-privilege credentials from online password spraying and brute-force guessing attacks:
* **Strict Lockout Threshold (5 attempts)**: On PAWs, the lockout threshold is set to 5 bad attempts (stricter than standard endpoints) because PAWs are high-value targets dedicated exclusively to directory administrators.
* **Duration & Observation Window (30 minutes)**: Setting lockout duration and reset intervals to 30 minutes prevents automated attacks from repeatedly guessing credentials across short time horizons.
* **Administrator Lockout**: Enabling Administrator account lockout prevents attackers from evading lockout protection by targeting the built-in Administrator account.

---

## Legacy Impact & Compatibility
* **Administrative Lockouts**: Repeatedly mistyping passwords on fallback local administrator accounts will trigger a temporary lockout. Standard procedures must exist for administrative unlocking.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policy`
4. Configure the settings:
   * **Account lockout threshold**: `5` invalid logon attempts
   * **Reset account lockout counter after**: `30` minutes
   * **Account lockout duration**: `30` minutes
   * **Allow Administrator account lockout**: `Enabled`
5. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options`
   * **Interactive logon: Machine account lockout threshold**: `10`

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountLockoutPolicy.ps1](../implementation_scripts/Configure-PawAccountLockoutPolicy.ps1)

```powershell
# Configure-PawAccountLockoutPolicy.ps1
Write-Host "Configuring PAW account lockout policy..." -ForegroundColor Cyan

# 1. Configure MaxDevicePasswordFailedAttempts via Registry
$SystemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $SystemPolicyPath)) { New-Item -Path $SystemPolicyPath -Force | Out-Null }
Set-ItemProperty -Path $SystemPolicyPath -Name "MaxDevicePasswordFailedAttempts" -Value 10 -Type DWord -Force

# 2. Configure SecEdit System Access lockout parameters
$SecTempDir = Join-Path $env:TEMP "PAWLockoutSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "paw_lockout.cfg"
$DbFile = Join-Path $SecTempDir "paw_lockout.sdb"
$LogFile = Join-Path $SecTempDir "paw_lockout.log"

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
    "LockoutBadCount"           = 5
    "ResetLockoutCount"         = 30
    "LockoutDuration"           = 30
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
Write-Host "PAW lockout policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountLockoutPolicyStatus.ps1](../audit_scripts/Get-PawAccountLockoutPolicyStatus.ps1)

```powershell
# Get-PawAccountLockoutPolicyStatus.ps1
Write-Host "--- Auditing PAW Account Lockout Policy ---" -ForegroundColor Cyan
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
$SecTempDir = Join-Path $env:TEMP "PAWLockoutAuditTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
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
