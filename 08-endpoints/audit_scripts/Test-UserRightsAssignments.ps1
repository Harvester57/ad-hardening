# Test-UserRightsAssignments.ps1
# Exports local user rights assignments and checks them against the baseline.

Write-Host "--- Auditing User Rights Assignments ---" -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "AuditSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "user_rights_audit.cfg"
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current configuration database."
    return
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
$BaselineRights = @{
    "SeTrustedCredManAccessPrivilege" = ""
    "SeNetworkLogonRight"             = "*S-1-5-32-544,*S-1-5-32-555"
    "SeTcbPrivilege"                  = ""
    "SeInteractiveLogonRight"         = "*S-1-5-32-544,*S-1-5-32-545"
    "SeBackupPrivilege"               = "*S-1-5-32-544"
    "SeSystemtimePrivilege"           = "*S-1-5-32-544,*S-1-5-19"
    "SeCreatePagefilePrivilege"       = "*S-1-5-32-544"
    "SeCreateTokenPrivilege"          = ""
    "SeCreateGlobalPrivilege"         = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeCreatePermanentPrivilege"      = ""
    "SeCreateSymbolicLinkPrivilege"   = "*S-1-5-32-544"
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

foreach ($Key in $BaselineRights.Keys) {
    $Expected = $BaselineRights[$Key]
    
    # Parse the exported config text to extract the privilege row
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    
    # Compare
    $Color = "Red"
    if ($Actual -eq $Expected) {
        $Color = "Green"
    }
    
    Write-Host "    - Privilege: $($Key) | Actual: '$($Actual)' (Expected: '$($Expected)')" -ForegroundColor $Color
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
