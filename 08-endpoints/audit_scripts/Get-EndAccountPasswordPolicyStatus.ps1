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
