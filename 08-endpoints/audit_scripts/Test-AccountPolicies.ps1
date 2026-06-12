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
