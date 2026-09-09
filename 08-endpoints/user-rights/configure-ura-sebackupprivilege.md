# [REQ-END-100] Configure User Rights: Back up files and directories

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-096](../../07-paws/user-rights/configure-ura-sebackupprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-110](../../02-domain-controllers/user-rights/configure-ura-sebackupprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Back up files and directories`
  * **Privilege Constant**: `SeBackupPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Back up files and directories`
  * **Registry Location**: Stored inside local security database under privilege `SeBackupPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeBackupPrivilege` grants the caller the capability to bypass all read-access security controls (Discretionary Access Control Lists - DACLs) across the entire NTFS filesystem and Windows Registry. When an application opens a file handle specifying the `FILE_FLAG_BACKUP_SEMANTICS` flag in Win32 `CreateFile` calls, the Windows kernel I/O manager and Object Manager explicitly bypass standard security descriptor evaluation. This design allows legitimate backup utilities to archive files without requiring explicit read permissions on every individual object.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries routinely target accounts holding `SeBackupPrivilege` for rapid credential harvesting and full domain escalation. Possession of this privilege allows an attacker to directly copy protected credential stores that are otherwise locked and ACL-protected by the operating system, including: (1) The Active Directory database file `ntds.dit` on Domain Controllers; (2) The local Security Account Manager (`SAM`) and `SYSTEM` registry hives on workstations and servers; (3) Sensitive configuration files, BitLocker recovery keys, and private certificates. Using standard tools such as `reg.exe save`, `wbadmin.exe`, Volume Shadow Copy Service (`vssadmin`), or PowerShell robocopy with `/b`, an attacker with `SeBackupPrivilege` can dump all password hashes and Kerberos keys across the entire domain.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

Restricting `SeBackupPrivilege` strictly to `Administrators` (S-1-5-32-544) prevents non-administrative users and compromised service accounts from abusing backup semantics to exfiltrate critical operating system secrets. On Tier 0 systems (Domain Controllers and PAWs), broad groups such as `Backup Operators` should be stripped of this right, and dedicated Group Managed Service Accounts (gMSAs) with tightly scoped time-limited access should be utilized for automated backup routines.

### 3. MITRE ATT&CK Mapping
* **T1003.002 - OS Credential Dumping: Security Account Manager**
* **T1003.003 - OS Credential Dumping: NTDS**
* **T1005 - Data from Local System**
* **T1083 - File and Directory Discovery**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeBackupPrivilege` prevents unauthorized read-bypass across system drives. Enterprise backup agents (e.g., Commvault, Veeam, NetBackup) that run under non-administrative service accounts may fail if they rely on `SeBackupPrivilege`; organizations must configure dedicated service identities or run backup software under managed accounts with explicit backup rights. Monitor Security Event ID 4672 and Event ID 4673 for invocations of `SeBackupPrivilege` outside of scheduled backup maintenance windows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Back up files and directories`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeBackupPrivilege.ps1](../implementation_scripts/Configure-UraSeBackupPrivilege.ps1)

```powershell
# Configure-UraSeBackupPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sebackupprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sebackupprivilege.sdb"
$LogFile = Join-Path $SecTempDir "secedit.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) { Throw "Failed to export security template" }

$ConfigText = Get-Content -Path $CfgFile -Raw
if ($ConfigText -notmatch "\[Privilege Rights\]") {
    $ConfigText += "`r`n[Privilege Rights]`r`n"
}

$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InPriv = $false
$KeyAdded = $false

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        if ($Matches[1] -eq "Privilege Rights") {
            $InPriv = $true
        } else {
            $InPriv = $false
        }
    }
    if ($InPriv -and $Line -match "^\s*SeBackupPrivilege\s*=") {
        $NewLines += "SeBackupPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeBackupPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeBackupPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeBackupPrivilegeStatus.ps1](../audit_scripts/Get-UraSeBackupPrivilegeStatus.ps1)

```powershell
# Get-UraSeBackupPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sebackupprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeBackupPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-544"
if ($CurrentValue -eq $Expected) {
    Write-Output "Compliant"
    exit 0
} else {
    Write-Output "Non-Compliant"
    exit 1
}
```

---

---

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: ANSSI Active Directory Hardening Guide: R28 (User Rights Assignment)
* **CIS Benchmark**: 2.2.4 (L1) Ensure 'Back up files and directories' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
