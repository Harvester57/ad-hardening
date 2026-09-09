# [REQ-PAW-109] Configure User Rights: Perform volume maintenance tasks for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-117](../../08-endpoints/user-rights/configure-ura-semanagevolumeprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

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
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

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
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Perform volume maintenance tasks`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeManageVolumePrivilege.ps1](../implementation_scripts/Configure-PawUraSeManageVolumePrivilege.ps1)

```powershell
# Configure-PawUraSeManageVolumePrivilege.ps1
# Configure-PawUraSeManageVolumePrivilege.ps1
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
[Download Script: Get-PawUraSeManageVolumePrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeManageVolumePrivilegeStatus.ps1)

```powershell
# Get-PawUraSeManageVolumePrivilegeStatus.ps1
# Get-PawUraSeManageVolumePrivilegeStatus.ps1
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
