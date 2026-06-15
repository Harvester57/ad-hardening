# Set-DCUserRightsAssignments.ps1
# Enforces the local user rights assignments baseline configuration on Domain Controllers using secedit.

Write-Host "Applying Domain Controller User Rights Assignments..." -ForegroundColor Cyan

# 1. Create a secure temporary path for security templates
$SecTempDir = Join-Path $env:TEMP "DCSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "dc_user_rights.cfg"
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

# Define the Domain Controller baseline User Rights Assignments
$BaselineRights = @{
    "SeNetworkLogonRight"             = "*S-1-5-9,*S-1-5-11,*S-1-5-32-544"
    "SeTcbPrivilege"                  = ""
    "SeMachineAccountPrivilege"       = "*S-1-5-32-544"
    "SeIncreaseQuotaPrivilege"        = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"
    "SeInteractiveLogonRight"         = "*S-1-5-9,*S-1-5-32-544"
    "SeRemoteInteractiveLogonRight"   = "*S-1-5-32-544"
    "SeBackupPrivilege"               = "*S-1-5-32-544"
    "SeChangeNotifyPrivilege"         = "*S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0"
    "SeSystemtimePrivilege"           = "*S-1-5-32-544,*S-1-5-19"
    "SeCreatePagefilePrivilege"       = "*S-1-5-32-544"
    "SeCreateTokenPrivilege"          = ""
    "SeCreatePermanentPrivilege"      = ""
    "SeDebugPrivilege"                = "*S-1-5-32-544"
    "SeDenyNetworkLogonRight"         = "*S-1-5-32-546"
    "SeDenyBatchLogonRight"           = "*S-1-5-32-546"
    "SeDenyServiceLogonRight"         = "*S-1-5-32-546"
    "SeDenyInteractiveLogonRight"     = "*S-1-5-32-546"
    "SeDenyRemoteInteractiveLogonRight" = "*S-1-5-32-546"
    "SeEnableDelegationPrivilege"     = "*S-1-5-32-544"
    "SeRemoteShutdownPrivilege"       = "*S-1-5-32-544"
    "SeAuditPrivilege"                = "*S-1-5-19,*S-1-5-20"
    "SeLoadDriverPrivilege"           = "*S-1-5-32-544"
    "SeLockMemoryPrivilege"           = ""
    "SeBatchLogonRight"               = "*S-1-5-32-544"
    "SeServiceLogonRight"             = ""
    "SeSecurityPrivilege"             = "*S-1-5-32-544"
    "SeSystemEnvironmentPrivilege"    = "*S-1-5-32-544"
    "SeProfileSingleProcessPrivilege" = "*S-1-5-32-544"
    "SeRestorePrivilege"              = "*S-1-5-32-544"
    "SeShutdownPrivilege"             = "*S-1-5-32-544"
    "SeSyncAgentPrivilege"            = ""
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

# Append our managed settings
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
    Write-Host "[+] DC User Rights Assignments applied successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to apply DC user rights assignments. Exit Code: $($Process.ExitCode)"
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
