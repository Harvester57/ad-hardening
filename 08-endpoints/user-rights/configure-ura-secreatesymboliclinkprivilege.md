# [REQ-END-107] Configure User Rights: Create symbolic links

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Create symbolic links`
  * **Privilege Constant**: `SeCreateSymbolicLinkPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create symbolic links`
  * **Registry Location**: Stored inside local security database under privilege `SeCreateSymbolicLinkPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeCreateSymbolicLinkPrivilege` controls the ability to create filesystem symbolic links (symlinks) via `CreateSymbolicLink` or `mklink`. Symbolic links are filesystem pointers that transparently redirect file and directory access to alternate target paths. While useful for software development and container workflows, unconstrained symbolic link creation represents one of the most common primitives for Local Privilege Escalation (LPE) in Windows.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries heavily exploit symbolic link creation in Time-of-Check to Time-of-Use (TOCTOU) and arbitrary file creation/deletion exploits. Privileged installer services (e.g., Windows Installer `msiexec`, scheduled tasks, or third-party updaters) frequently create temporary files in user-writable directories (such as `C:\Windows\Temp` or `C:\Users\<User>\AppData\Local\Temp`) and subsequently write data to them running as `NT AUTHORITY\SYSTEM`. An unprivileged attacker holding `SeCreateSymbolicLinkPrivilege` can create a symlink pointing from the predictable temporary file to a protected system binary (e.g., `C:\Windows\System32\svchost.exe` or an AppLocker configuration file), tricking the privileged installer into overwriting or modifying critical system files.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). Restricting symlink creation prevents standard users and low-integrity malware from mounting file system redirection attacks against elevated system services.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**
* **T1574 - Hijack Execution Flow**
* **T1222.001 - File and Directory Permissions Modification: Windows DACL**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeCreateSymbolicLinkPrivilege` to `Administrators` mitigates TOCTOU symlink vulnerabilities. Software developers utilizing local symlink creation in developer toolchains (e.g., Node.js symlinks, Python virtual environments, or Git symlinks) may encounter errors when running as standard non-elevated users; in developer environments, Windows Developer Mode or elevated command prompts may be required. Monitor Event ID 4672 for symlink privilege allocations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Create symbolic links`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeCreateSymbolicLinkPrivilege.ps1](../implementation_scripts/Configure-UraSeCreateSymbolicLinkPrivilege.ps1)

```powershell
# Configure-UraSeCreateSymbolicLinkPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreatesymboliclinkprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreatesymboliclinkprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreateSymbolicLinkPrivilege\s*=") {
        $NewLines += "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeCreateSymbolicLinkPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeCreateSymbolicLinkPrivilegeStatus.ps1](../audit_scripts/Get-UraSeCreateSymbolicLinkPrivilegeStatus.ps1)

```powershell
# Get-UraSeCreateSymbolicLinkPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreatesymboliclinkprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreateSymbolicLinkPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.11 (L1) Ensure 'Create symbolic links' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
