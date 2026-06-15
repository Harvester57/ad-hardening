# [REQ-DC-023] Configure User Rights Assignments for Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (DCs)
* **Operating Systems**: Windows Server 2016 and above

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
  * **Registry Location**: Configured via Local Security Database template (`secedit` Privilege Rights area).

---

## Rationale
User Rights Assignments (URAs) define the actions that groups or individual accounts can perform on Domain Controllers. In a standard installation, default Windows groups such as `Server Operators`, `Backup Operators`, `Print Operators`, and `Account Operators` are granted extensive local privileges. On Domain Controllers, these groups are effectively Tier 0 administration pathways:
1. **Interactive Logon (`SeInteractiveLogonRight`)**: Default settings allow Print, Server, Account, and Backup Operators to log on locally to Domain Controllers. An attacker who compromises a member of these groups can log on interactively to a Domain Controller and execute commands, bypassing tiering boundaries.
2. **System Shutdown (`SeShutdownPrivilege` / `SeRemoteShutdownPrivilege`)**: Print, Server, and Backup Operators can shut down Domain Controllers locally or remotely, presenting a denial-of-service vector.
3. **Backup and Restore (`SeBackupPrivilege` / `SeRestorePrivilege`)**: Server and Backup Operators bypass all NTFS ACLs to back up and restore files. Attackers with these privileges can read the NTDS database (`ntds.dit`) or write files directly to DC directories.
4. **Device Drivers (`SeLoadDriverPrivilege`)**: Print Operators are allowed to load and unload device drivers on Domain Controllers. This privilege can be exploited to load signed vulnerable drivers (BYOVD) to achieve kernel-mode execution.

To preserve the Tier 0 administrative boundary, these rights must be restricted strictly to local Administrators and essential network services, removing the default operator group assignments.

---

## Legacy Impact & Compatibility
* **Backup Software**: Dedicated backup software or monitoring agents running under service accounts may require `SeBackupPrivilege` or `SeRestorePrivilege` to function. If backups fail on Domain Controllers, configure dedicated, isolated service accounts with these privileges through the DC Hardening GPO.
* **Server Operators delegation**: Traditional Server Operators will no longer be able to log on interactively or shut down Domain Controllers. All administrative tasks must be delegated via standard Tier 0 accounts and secure jump hosts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`) on a management workstation.
2. Edit the modular Domain Controllers GPO (e.g., `SEC_DomainControllers_Hardening`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Configure the following policies as specified, removing any default operator group entries (such as Backup Operators, Print Operators, Server Operators, and Account Operators):

| Policy Setting | Allowed Security Principals (SIDs / Groups) |
| :--- | :--- |
| **Access this computer from the network** | `BUILTIN\Administrators`, `NT AUTHORITY\Authenticated Users`, `NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS` |
| **Act as part of the operating system** | No one (Empty) |
| **Add workstations to domain** | `BUILTIN\Administrators` |
| **Adjust memory quotas for a process** | `BUILTIN\Administrators`, `NT AUTHORITY\LOCAL SERVICE`, `NT AUTHORITY\NETWORK SERVICE` |
| **Allow log on locally** | `BUILTIN\Administrators`, `NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS` |
| **Allow log on through Remote Desktop Services** | `BUILTIN\Administrators` |
| **Back up files and directories** | `BUILTIN\Administrators` |
| **Bypass traverse checking** | `BUILTIN\Pre-Windows 2000 Compatible Access`, `NT AUTHORITY\Authenticated Users`, `BUILTIN\Administrators`, `NT AUTHORITY\NETWORK SERVICE`, `NT AUTHORITY\LOCAL SERVICE`, `Everyone` |
| **Change the system time** | `BUILTIN\Administrators`, `NT AUTHORITY\LOCAL SERVICE` |
| **Create a pagefile** | `BUILTIN\Administrators` |
| **Create a token object** | No one (Empty) |
| **Create permanent shared objects** | No one (Empty) |
| **Debug programs** | `BUILTIN\Administrators` |
| **Deny access to this computer from the network** | `BUILTIN\Guests` |
| **Deny log on as a batch job** | `BUILTIN\Guests` |
| **Deny log on as a service** | `BUILTIN\Guests` |
| **Deny log on locally** | `BUILTIN\Guests` |
| **Deny log on through Remote Desktop Services** | `BUILTIN\Guests` |
| **Enable computer and user accounts to be trusted for delegation** | `BUILTIN\Administrators` |
| **Force shutdown from a remote system** | `BUILTIN\Administrators` |
| **Generate security audits** | `NT AUTHORITY\LOCAL SERVICE`, `NT AUTHORITY\NETWORK SERVICE` |
| **Load and unload device drivers** | `BUILTIN\Administrators` |
| **Lock pages in memory** | No one (Empty) |
| **Log on as a batch job** | `BUILTIN\Administrators` |
| **Log on as a service** | No one (Empty) |
| **Manage auditing and security log** | `BUILTIN\Administrators` |
| **Modify firmware environment values** | `BUILTIN\Administrators` |
| **Profile single process** | `BUILTIN\Administrators` |
| **Restore files and directories** | `BUILTIN\Administrators` |
| **Shut down the system** | `BUILTIN\Administrators` |
| **Synchronize directory service data** | No one (Empty) |
| **Take ownership of files or other objects** | `BUILTIN\Administrators` |

5. Ensure the GPO is linked to the **Domain Controllers** OU and has higher precedence (Link Order 1) than the Default Domain Controllers Policy.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Configure Domain Controller User Rights Assignments locally using `secedit.exe` and PowerShell.

[Download Script: Set-DCUserRightsAssignments.ps1](implementation_scripts/Set-DCUserRightsAssignments.ps1)

```powershell
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
```

*To audit local Domain Controller User Rights Assignments:*

[Download Script: Get-DCUserRightsAssignmentsStatus.ps1](audit_scripts/Get-DCUserRightsAssignmentsStatus.ps1)

```powershell
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
```

---

## Sources & Compliance References
* **CIS Active Directory and Group Policy Management Best Practices**: Appendix B (Default Domain Controller Policy vs CIS Recommendations) (Page 45)
* **ANSSI AD Hardening Guide**: Recommendations R2, R4, and general privilege minimization.
* **DoD Windows Server Domain Controller Security Technical Implementation Guide (STIG)**: DC User Rights Assignment parameters.
