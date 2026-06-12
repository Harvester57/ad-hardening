# Set-AccountPolicies.ps1
# Description: Configures local account lockout, password parameters (via secedit), smart card behavior, and blank password blocks.

Write-Host "Applying account and password policies..." -ForegroundColor Cyan

# 1. Enforce local security options via Registry
$WinlogonPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (-not (Test-Path $WinlogonPath)) {
    New-Item -Path $WinlogonPath -Force | Out-Null
}
# ScRemoveOption: "1" = Lock Workstation, "2" = Force Logoff
Set-ItemProperty -Path $WinlogonPath -Name "ScRemoveOption" -Value "1" -Type String
Write-Host "[+] Smart card removal behavior set to Lock Workstation." -ForegroundColor Green

$LsaPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
if (-not (Test-Path $LsaPath)) {
    New-Item -Path $LsaPath -Force | Out-Null
}
Set-ItemProperty -Path $LsaPath -Name "LimitBlankPasswordUse" -Value 1 -Type DWord
Write-Host "[+] Blank password restriction enforced." -ForegroundColor Green

# 2. Enforce Account Lockout and Password Policy via secedit
$SecTempDir = Join-Path $env:TEMP "AccountSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "account_sec.cfg"
$LogFile = Join-Path $SecTempDir "secedit.log"
$DbFile = Join-Path $SecTempDir "secedit.sdb"

# Export current db
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current configuration database."
    return
}

$ConfigText = Get-Content -Path $CfgFile -Raw
$HasSystemAccess = $ConfigText -match "\[System Access\]"
if (-not $HasSystemAccess) {
    $ConfigText += "`r`n[System Access]`r`n"
}

# Re-build [System Access] section line-by-line
$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InSystemAccess = $false

$AccountSettings = @{
    "LockoutBadCount"     = 10
    "ResetLockoutCount"   = 15
    "LockoutDuration"     = 15
    "ClearTextPassword"   = 0
}

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        $SectionName = $Matches[1]
        if ($SectionName -eq "System Access") {
            $InSystemAccess = $true
            $NewLines += $Line
            continue
        } else {
            $InSystemAccess = $false
        }
    }
    
    if ($InSystemAccess) {
        $IsManaged = $false
        foreach ($Key in $AccountSettings.Keys) {
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

# Append our settings
$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[System Access]") {
        foreach ($Key in $AccountSettings.Keys) {
            $Val = $AccountSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force

# Import
$Process = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "[+] Lockout and password policies applied locally." -ForegroundColor Green
} else {
    Write-Error "Failed to apply local account policies. Exit Code: $($Process.ExitCode)"
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
