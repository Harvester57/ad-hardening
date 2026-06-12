# Set-UserRightsAssignments.ps1
# Description: Enforces the local user rights assignments baseline configuration using secedit templates.

Write-Host "Applying User Rights Assignments hardening..." -ForegroundColor Cyan

# 1. Create a secure temporary path for security templates
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "user_rights.cfg"
$LogFile = Join-Path $SecTempDir "secedit.log"
$DbFile = Join-Path $SecTempDir "secedit.sdb"

# 2. Export current security configuration
Write-Host "[*] Exporting current security configuration..." -ForegroundColor Gray
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current security database settings."
    return
}

# 3. Read and modify the configuration file
$ConfigText = Get-Content -Path $CfgFile -Raw
$HasPrivilegeSection = $ConfigText -match "\[Privilege Rights\]"

if (-not $HasPrivilegeSection) {
    $ConfigText += "`r`n[Privilege Rights]`r`n"
}

# Define the baseline User Rights Assignments
$BaselineRights = @{
    "SeTrustedCredManAccessPrivilege" = ""
    "SeNetworkLogonRight"             = "*S-1-5-32-544,*S-1-5-32-555"
    "SeTcbPrivilege"                  = ""
    "SeInteractiveLogonRight"         = "*S-1-5-32-544,*S-1-5-32-545"
    "SeBackupPrivilege"               = "*S-1-5-32-544"
    "SeCreatePagefilePrivilege"       = "*S-1-5-32-544"
    "SeCreateTokenPrivilege"          = ""
    "SeCreateGlobalPrivilege"         = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeCreatePermanentPrivilege"      = ""
    "SeDebugPrivilege"                = "*S-1-5-32-544"
    "SeEnableDelegationPrivilege"     = ""
    "SeRemoteShutdownPrivilege"       = "*S-1-5-32-544"
    "SeImpersonatePrivilege"          = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeLoadDriverPrivilege"           = "*S-1-5-32-544"
    "SeLockMemoryPrivilege"           = ""
    "SeSecurityPrivilege"             = "*S-1-5-32-544"
    "SeSystemEnvironmentPrivilege"    = "*S-1-5-32-544"
    "SeManageVolumePrivilege"         = "*S-1-5-32-544"
    "SeProfileSingleProcessPrivilege" = "*S-1-5-32-544"
    "SeRestorePrivilege"              = "*S-1-5-32-544"
    "SeTakeOwnershipPrivilege"        = "*S-1-5-32-544"
}

# Re-build [Privilege Rights] section line-by-line
$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InPrivilegeSection = $false

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        $SectionName = $Matches[1]
        if ($SectionName -eq "Privilege Rights") {
            $InPrivilegeSection = $true
            $NewLines += $Line
            continue
        } else {
            $InPrivilegeSection = $false
        }
    }
    
    if ($InPrivilegeSection) {
        # Skip line if it contains a URA we manage
        $IsManaged = $false
        foreach ($Key in $BaselineRights.Keys) {
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

# Append our managed settings into the Privilege section
$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[Privilege Rights]") {
        foreach ($Key in $BaselineRights.Keys) {
            $Val = $BaselineRights[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force

# 4. Import the modified configuration file
Write-Host "[*] Importing updated security configuration template..." -ForegroundColor Gray
$Process = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -eq 0) {
    Write-Host "[+] User Rights Assignments applied successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to apply user rights assignments. Exit Code: $($Process.ExitCode)"
}

# Clean up temp files
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
