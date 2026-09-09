# [REQ-DC-132] Configure User Rights: Restore files and directories on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-111](../../07-paws/user-rights/configure-ura-serestoreprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-121](../../08-endpoints/user-rights/configure-ura-serestoreprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Restore files and directories`
  * **Privilege Constant**: `SeRestorePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Restore files and directories`
  * **Registry Location**: Stored inside local security database under privilege `SeRestorePrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeRestorePrivilege` grants the caller the capability to bypass all write-access security controls (DACLs) across the entire NTFS filesystem and Windows Registry. When a process opens a file or registry key handle specifying `FILE_FLAG_BACKUP_SEMANTICS` in Win32 APIs, the kernel explicitly bypasses standard security descriptor DACL checks, allowing the process to write to, overwrite, or delete any file or key on the system. In addition, this privilege grants the ability to set any valid user or group SID as the owner of an object.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary who obtains `SeRestorePrivilege` has immediate, trivial local privilege escalation to `NT AUTHORITY\SYSTEM`: (1) System File Replacement: The attacker can overwrite core operating system binaries or DLLs (e.g., `C:\Windows\System32\utilman.exe`, `osk.exe`, or service DLLs) with malicious payloads, which execute automatically as SYSTEM upon reboot or logon; (2) Registry Service Hijacking: The attacker can overwrite protected registry keys under `HKLM\SYSTEM\CurrentControlSet\Services` to change service binary paths (`ImagePath`) to point to malicious executables; (3) SAM/SECURITY Hive Overwriting: The attacker can overwrite local account password hashes or security settings directly.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted strictly to `Administrators` (S-1-5-32-544). Broad groups such as `Backup Operators` should be stripped of this privilege on Tier 0 systems (Domain Controllers and PAWs). Automated enterprise restore agents should operate under tightly controlled, dedicated service identities.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**
* **T1574 - Hijack Execution Flow**
* **T1543.003 - Create or Modify System Process: Windows Service**
* **T1222.001 - File and Directory Permissions Modification: Windows DACL**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeRestorePrivilege` prevents write-bypass exploitation while preserving standard file access controls. Enterprise disaster recovery tools running under non-administrative accounts will require explicit delegation or membership in a dedicated restore management role. Monitor Security Event ID 4672 and Event ID 4673 for invocations of `SeRestorePrivilege`.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Restore files and directories`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeRestorePrivilege.ps1](../implementation_scripts/Configure-DcUraSeRestorePrivilege.ps1)

```powershell
# Configure-DcUraSeRestorePrivilege.ps1
# Configure-DcUraSeRestorePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_serestoreprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_serestoreprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeRestorePrivilege\s*=") {
        $NewLines += "SeRestorePrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeRestorePrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeRestorePrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeRestorePrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeRestorePrivilegeStatus.ps1)

```powershell
# Get-DcUraSeRestorePrivilegeStatus.ps1
# Get-DcUraSeRestorePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_serestoreprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeRestorePrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.35 (L1) Ensure 'Restore files and directories' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
