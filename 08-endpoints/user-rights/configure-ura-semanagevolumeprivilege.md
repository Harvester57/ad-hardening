# [REQ-END-117] Configure User Rights: Perform volume maintenance tasks

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-109](../../07-paws/user-rights/configure-ura-semanagevolumeprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Perform volume maintenance tasks`
  * **Privilege Constant**: `SeManageVolumePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Perform volume maintenance tasks`
  * **Registry Location**: Stored inside local security database under privilege `SeManageVolumePrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeManageVolumePrivilege` allows a process to perform low-level disk and volume maintenance tasks, including running defragmentation tools, modifying volume quotas, and invoking the `SetFileValidData` Win32 API. The `SetFileValidData` function allows a caller to extend the valid data length of an allocated file without zeroing out the intervening disk clusters.

### 1. Technical Threat Vector & Abuse Mechanics
The capability to bypass cluster zeroing via `SetFileValidData` represents a severe information disclosure vulnerability: (1) Uninitialized Disk Sector Harvesting: Operating systems typically write zeros to newly allocated disk clusters to prevent users from seeing remnants of previously stored data. When an attacker with `SeManageVolumePrivilege` invokes `SetFileValidData`, the file length is extended across physical clusters containing remnants of deleted files, memory crash dumps, pagefile fragments, or BitLocker keys; (2) Direct Credential Theft: The attacker can immediately read the raw cluster data, harvesting cleartext passwords, encryption certificates, and sensitive documents without possessing read permissions on the original deleted objects.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). Standard users, interactive accounts, and third-party software must not hold volume maintenance rights. Restricting this right ensures that NTFS cluster zero-initialization cannot be bypassed.

### 3. MITRE ATT&CK Mapping
* **T1005 - Data from Local System**
* **T1006 - Direct Volume Access**
* **T1083 - File and Directory Discovery**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeManageVolumePrivilege` to `Administrators` prevents unauthorized disk cluster inspection. Enterprise database engines (such as Microsoft SQL Server utilizing Instant File Initialization) require this privilege to pre-allocate database data files quickly; on dedicated database servers, the database service account should be granted this right in a targeted server policy. Auditing is captured via Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Perform volume maintenance tasks`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeManageVolumePrivilege.ps1](../implementation_scripts/Configure-UraSeManageVolumePrivilege.ps1)

```powershell
# Configure-UraSeManageVolumePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_semanagevolumeprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_semanagevolumeprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeManageVolumePrivilege\s*=") {
        $NewLines += "SeManageVolumePrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeManageVolumePrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeManageVolumePrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeManageVolumePrivilegeStatus.ps1](../audit_scripts/Get-UraSeManageVolumePrivilegeStatus.ps1)

```powershell
# Get-UraSeManageVolumePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_semanagevolumeprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeManageVolumePrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
