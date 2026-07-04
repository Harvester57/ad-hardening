# [REQ-END-016] Configure User Rights Assignments

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients (Windows 10/11)
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: High
* **Assessment**: Manual
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Stored inside the local Security Database (`secedit` under User Rights Area).

---

## Rationale
User Rights Assignments (URAs) govern the specific actions that security principals (users, groups, and service accounts) can perform on a system. Insecure default URA mappings can be abused by attackers to elevate privileges, compromise credentials, or establish persistence:

1. **LSASS Memory Dumping (`SeDebugPrivilege`)**: The Debug Programs privilege allows a process to attach to and debug any system process. If this privilege is held by a compromised admin account or a local service, tools like Mimikatz can read LSASS memory to extract cleartext passwords and Kerberos keys. It must be restricted strictly to local Administrators.
2. **Token Impersonation (`SeImpersonatePrivilege` / `SeCreateGlobalPrivilege`)**: The Impersonate Client privilege allows a service or user to run code in the security context of another user. Attackers exploit this privilege (using "Potato" exploits) to coerce local services (like Print Spooler or IIS) into authenticating to them, allowing the attacker to steal the service's SYSTEM token. It must be restricted to Administrators and local service identities.
3. **Backup and Restore Access (`SeBackupPrivilege` / `SeRestorePrivilege`)**: The Backup/Restore privileges bypass all file-system Access Control Lists (ACLs) to read or write any file. Attackers use these rights to dump the local SAM database, registry hives, or confidential directories.
4. **Network and Local Logon Access (`SeNetworkLogonRight` / `SeInteractiveLogonRight`)**: Restricting network logon permissions limits lateral movement options for standard domain accounts, containing potential compromises.
5. **Deny Local Account Remote Logon (`SeDenyNetworkLogonRight` / `SeDenyRemoteInteractiveLogonRight`)**: Blocking network and Remote Desktop logons for local accounts (SIDs `S-1-5-113` and `S-1-5-114`) prevents lateral movement. If a local account is compromised, the attacker cannot leverage Pass-the-Hash or cleartext authentication to connect remotely to other systems using that local account context.

---

## Legacy Impact & Compatibility
* **Service Account Operations**: Certain third-party agents, backup programs, database servers, and monitoring platforms require specific privileges (such as `SeBackupPrivilege`, `SeImpersonatePrivilege`, or `SeServiceLogonRight`) to function. Standard service accounts must be analyzed and added to the GPO if legitimate operations fail.
* **Administrative Tooling**: Administrative tools that require system debugging or hardware level configuration may require `SeDebugPrivilege` or `SeLoadDriverPrivilege` which remain allocated to the local Administrators group.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management workstation.
2. Create or edit a GPO targeting endpoints (e.g., `GPO_Hardening_UserRights_Workstations`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Configure the following policies as specified:

| Policy Setting | Allowed Security Principals (SIDs / Groups) |
| :--- | :--- |
| **Access Credential Manager as a trusted caller** | No one (Empty) |
| **Access this computer from the network** | `BUILTIN\Administrators`, `BUILTIN\Remote Desktop Users` |
| **Act as part of the operating system** | No one (Empty) |
| **Allow log on locally** | `BUILTIN\Administrators`, `BUILTIN\Users` |
| **Back up files and directories** | `BUILTIN\Administrators` |
| **Change the system time** | `BUILTIN\Administrators`, `NT SERVICE\LocalService` |
| **Change the time zone** | `BUILTIN\Administrators`, `NT SERVICE\LocalService`, `BUILTIN\Users` |
| **Create a pagefile** | `BUILTIN\Administrators` |
| **Create a token object** | No one (Empty) |
| **Create global objects** | `Administrators`, `LOCAL SERVICE`, `NETWORK SERVICE`, `SERVICE` |
| **Create permanent shared objects** | No one (Empty) |
| **Create symbolic links** | `BUILTIN\Administrators` |
| **Debug programs** | `BUILTIN\Administrators` |
| **Enable computer and user accounts to be trusted for delegation** | No one (Empty) |
| **Force shutdown from a remote system** | `BUILTIN\Administrators` |
| **Impersonate a client after authentication** | `Administrators`, `LOCAL SERVICE`, `NETWORK SERVICE`, `SERVICE` |
| **Increase scheduling priority** | `BUILTIN\Administrators`, `Window Manager\Window Manager Group` |
| **Load and unload device drivers** | `BUILTIN\Administrators` |
| **Lock pages in memory** | No one (Empty) |
| **Manage auditing and security log** | `BUILTIN\Administrators` |
| **Modify an object label** | No one (Empty) |
| **Modify firmware environment values** | `BUILTIN\Administrators` |
| **Perform volume maintenance tasks** | `BUILTIN\Administrators` |
| **Profile single process** | `BUILTIN\Administrators` |
| **Profile system performance** | `BUILTIN\Administrators`, `NT SERVICE\WdiServiceHost` |
| **Replace a process level token** | `LOCAL SERVICE`, `NETWORK SERVICE` |
| **Deny access to this computer from the network** | Local account (SID `S-1-5-113`), Local account and member of Administrators group (SID `S-1-5-114`) |
| **Deny log on through Remote Desktop Services** | Local account (SID `S-1-5-113`), Local account and member of Administrators group (SID `S-1-5-114`) |
| **Restore files and directories** | `BUILTIN\Administrators` |
| **Take ownership of files or other objects** | `BUILTIN\Administrators` |

5. Link the GPO to the appropriate Organizational Unit (OU).

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure User Rights Assignments locally using `secedit.exe` and PowerShell.

[Download Script: Set-UserRightsAssignments.ps1](implementation_scripts/Set-UserRightsAssignments.ps1)

```powershell
# Set-UserRightsAssignments.ps1
# Enforces the local user rights assignments baseline configuration using secedit templates.

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
    "SeSystemtimePrivilege"           = "*S-1-5-32-544,*S-1-5-19"
    "SeTimeZonePrivilege"             = "*S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"
    "SeCreatePagefilePrivilege"       = "*S-1-5-32-544"
    "SeCreateTokenPrivilege"          = ""
    "SeCreateGlobalPrivilege"         = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeCreatePermanentPrivilege"      = ""
    "SeCreateSymbolicLinkPrivilege"   = "*S-1-5-32-544"
    "SeDebugPrivilege"                = "*S-1-5-32-544"
    "SeEnableDelegationPrivilege"     = ""
    "SeRemoteShutdownPrivilege"       = "*S-1-5-32-544"
    "SeImpersonatePrivilege"          = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeIncreaseBasePriorityPrivilege" = "*S-1-5-32-544,*S-1-5-90-0"
    "SeLoadDriverPrivilege"           = "*S-1-5-32-544"
    "SeLockMemoryPrivilege"           = ""
    "SeSecurityPrivilege"             = "*S-1-5-32-544"
    "SeSystemEnvironmentPrivilege"    = "*S-1-5-32-544"
    "SeManageVolumePrivilege"         = "*S-1-5-32-544"
    "SeProfileSingleProcessPrivilege" = "*S-1-5-32-544"
    "SeSystemProfilePrivilege"        = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
    "SeAssignPrimaryTokenPrivilege"   = "*S-1-5-19,*S-1-5-20"
    "SeRestorePrivilege"              = "*S-1-5-32-544"
    "SeTakeOwnershipPrivilege"        = "*S-1-5-32-544"
    "SeRelabelPrivilege"              = ""
    "SeDenyNetworkLogonRight"             = "*S-1-5-113,*S-1-5-114"
    "SeDenyRemoteInteractiveLogonRight"   = "*S-1-5-113,*S-1-5-114"
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
```

*To audit local User Rights Assignments:*
[Download Script: Test-UserRightsAssignments.ps1](audit_scripts/Test-UserRightsAssignments.ps1)

```powershell
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
    "SeTimeZonePrivilege"             = "*S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"
    "SeCreatePagefilePrivilege"       = "*S-1-5-32-544"
    "SeCreateTokenPrivilege"          = ""
    "SeCreateGlobalPrivilege"         = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeCreatePermanentPrivilege"      = ""
    "SeCreateSymbolicLinkPrivilege"   = "*S-1-5-32-544"
    "SeDebugPrivilege"                = "*S-1-5-32-544"
    "SeEnableDelegationPrivilege"     = ""
    "SeRemoteShutdownPrivilege"       = "*S-1-5-32-544"
    "SeImpersonatePrivilege"          = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    "SeIncreaseBasePriorityPrivilege" = "*S-1-5-32-544,*S-1-5-90-0"
    "SeLoadDriverPrivilege"           = "*S-1-5-32-544"
    "SeLockMemoryPrivilege"           = ""
    "SeSecurityPrivilege"             = "*S-1-5-32-544"
    "SeSystemEnvironmentPrivilege"    = "*S-1-5-32-544"
    "SeManageVolumePrivilege"         = "*S-1-5-32-544"
    "SeProfileSingleProcessPrivilege" = "*S-1-5-32-544"
    "SeSystemProfilePrivilege"        = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
    "SeAssignPrimaryTokenPrivilege"   = "*S-1-5-19,*S-1-5-20"
    "SeRestorePrivilege"              = "*S-1-5-32-544"
    "SeTakeOwnershipPrivilege"        = "*S-1-5-32-544"
    "SeRelabelPrivilege"              = ""
    "SeDenyNetworkLogonRight"             = "*S-1-5-113,*S-1-5-114"
    "SeDenyRemoteInteractiveLogonRight"   = "*S-1-5-113,*S-1-5-114"
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
```

---

## 🔗 Sources & Compliance References
* **CIS Microsoft Windows 10/11 Benchmark**: Section 2.2 (User Rights Assignment)
* **ANSSI AD Hardening Guide**: Recommendations on restricting privileged capabilities and limiting local privileges on administrative workstations
* **DoD Windows 11 STIG**: User Rights Assignment settings for SeSystemtimePrivilege and SeCreateSymbolicLinkPrivilege.
