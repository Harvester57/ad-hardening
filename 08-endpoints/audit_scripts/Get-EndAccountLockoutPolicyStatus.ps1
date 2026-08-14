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
