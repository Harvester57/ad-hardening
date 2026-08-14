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
