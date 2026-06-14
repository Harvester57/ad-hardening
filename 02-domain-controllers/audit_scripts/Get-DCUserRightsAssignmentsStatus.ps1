# Get-DCUserRightsAssignmentsStatus.ps1
# Description: Exports DC user rights assignments and checks them against the baseline.

Write-Host "--- Auditing DC User Rights Assignments ---" -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP -ChildPath "DCAuditSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "dc_user_rights_audit.cfg"
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current configuration database."
    return
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
$BaselineRights = @{
    "SeNetworkLogonRight"             = "*S-1-5-9,*S-1-5-11,*S-1-5-32-544"
    "SeTcbPrivilege"                  = ""
    "SeMachineAccountPrivilege"       = "*S-1-5-32-544"
    "SeIncreaseQuotaPrivilege"        = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"
    "SeInteractiveLogonRight"         = "*S-1-5-9,*S-1-5-32-544"
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
    "SeEnableDelegationPrivilege"     = "*S-1-5-32-544"
    "SeRemoteShutdownPrivilege"       = "*S-1-5-32-544"
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

$vulnerable = $false

foreach ($Key in $BaselineRights.Keys) {
    $Expected = $BaselineRights[$Key]
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    
    $Color = "Green"
    if ($Actual -ne $Expected) {
        $Color = "Red"
        $vulnerable = $true
    }
    Write-Host "    - Privilege: $($Key) | Actual: '$($Actual)' (Expected: '$($Expected)')" -ForegroundColor $Color
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

if ($vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
}
