# Hardening Requirement: Configure User Rights Assignments for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Configured via Group Policy or local Security Database (`secedit` templates).

---

## Rationale
Privileged Access Workstations (PAWs) host the most sensitive credentials in the enterprise. To prevent credential theft, session hijacking, or administrative privilege escalation, User Rights Assignments (URAs) must be hardened to the highest standard:

1. **Deny Standard Users Local Logon (`SeInteractiveLogonRight`)**: Unlike standard endpoints, standard domain users must never log on to a PAW. Only dedicated Tier 0 administrators are allowed console access. Removing `BUILTIN\Users` from local logon rights ensures standard users cannot execute local code on a PAW.
2. **Restrict Network Access (`SeNetworkLogonRight`)**: Restricting network access strictly to local Administrators prevents domain users from initiating network-based connections to the PAW, cutting off remote exploitation paths.
3. **Restricting Debugging and Impersonation (`SeDebugPrivilege` / `SeImpersonatePrivilege`)**: Restricting these rights to the built-in local Administrators group prevents any running application from dumping LSA memory or hijacking service tokens.

---

## Legacy Impact & Compatibility
* **Dedicated Admin Accounts Required**: Administrators must use dedicated Tier 0 administrative accounts to authenticate to the console of a PAW. Standard domain user accounts will be blocked from logging on.
* **Management Overhead**: Service mappings must be verified. All operations on PAWs must execute under the local Administrator or authorized administrative accounts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the PAW GPO (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Configure the following policies as specified:

| Policy Setting | Allowed Security Principals (SIDs / Groups) |
| :--- | :--- |
| **Access Credential Manager as a trusted caller** | No one (Empty) |
| **Access this computer from the network** | `BUILTIN\Administrators` |
| **Act as part of the operating system** | No one (Empty) |
| **Allow log on locally** | `BUILTIN\Administrators` |
| **Back up files and directories** | `BUILTIN\Administrators` |
| **Create a pagefile** | `BUILTIN\Administrators` |
| **Create a token object** | No one (Empty) |
| **Create global objects** | `Administrators`, `LOCAL SERVICE`, `NETWORK SERVICE`, `SERVICE` |
| **Create permanent shared objects** | No one (Empty) |
| **Debug programs** | `BUILTIN\Administrators` |
| **Enable computer and user accounts to be trusted for delegation** | No one (Empty) |
| **Force shutdown from a remote system** | `BUILTIN\Administrators` |
| **Impersonate a client after authentication** | `Administrators`, `LOCAL SERVICE`, `NETWORK SERVICE`, `SERVICE` |
| **Load and unload device drivers** | `BUILTIN\Administrators` |
| **Lock pages in memory** | No one (Empty) |
| **Manage auditing and security log** | `BUILTIN\Administrators` |
| **Modify firmware environment values** | `BUILTIN\Administrators` |
| **Perform volume maintenance tasks** | `BUILTIN\Administrators` |
| **Profile single process** | `BUILTIN\Administrators` |
| **Restore files and directories** | `BUILTIN\Administrators` |
| **Take ownership of files or other objects** | `BUILTIN\Administrators` |

5. Link the GPO to the PAWs Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure User Rights Assignments locally on the PAW using `secedit.exe` and PowerShell.

```powershell
# Set-PawUserRightsAssignments.ps1
# Description: Enforces the PAW user rights assignments baseline configuration using secedit templates.

Write-Host "Applying PAW User Rights Assignments hardening..." -ForegroundColor Cyan

# 1. Create a secure temporary path for security templates
$SecTempDir = Join-Path $env:TEMP "PawSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_user_rights.cfg"
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

# Define the baseline User Rights Assignments (Stricter for PAWs)
$BaselineRights = @{
    "SeTrustedCredManAccessPrivilege" = ""
    "SeNetworkLogonRight"             = "*S-1-5-32-544"
    "SeTcbPrivilege"                  = ""
    "SeInteractiveLogonRight"         = "*S-1-5-32-544"
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
    Write-Host "[+] PAW User Rights Assignments applied successfully." -ForegroundColor Green
} else {
    Write-Error "Failed to apply PAW user rights assignments. Exit Code: $($Process.ExitCode)"
}

# Clean up temp files
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
```

*To audit local PAW User Rights Assignments:*
```powershell
# Test-PawUserRightsAssignments.ps1
# Description: Exports local user rights assignments and checks them against the PAW baseline.

Write-Host "--- Auditing PAW User Rights Assignments ---" -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "PawAuditSecurityTemplates"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_user_rights_audit.cfg"
$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Error "Failed to export current configuration database."
    return
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
$BaselineRights = @{
    "SeTrustedCredManAccessPrivilege" = ""
    "SeNetworkLogonRight"             = "*S-1-5-32-544"
    "SeTcbPrivilege"                  = ""
    "SeInteractiveLogonRight"         = "*S-1-5-32-544"
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

foreach ($Key in $BaselineRights.Keys) {
    $Expected = $BaselineRights[$Key]
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    
    $Color = "Red"
    if ($Actual -eq $Expected) {
        $Color = "Green"
    }
    Write-Host "    - Privilege: $($Key) | Actual: '$($Actual)' (Expected: '$($Expected)')" -ForegroundColor $Color
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
```

---

## Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.2 (User Rights Assignment)
* **ANSSI AD Hardening Guide**: Recommendations on administrative workstation isolation and URA restrictions
