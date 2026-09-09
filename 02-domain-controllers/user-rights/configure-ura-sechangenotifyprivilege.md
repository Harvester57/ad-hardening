# [REQ-DC-111] Configure User Rights: Bypass traverse checking on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Bypass traverse checking`
  * **Privilege Constant**: `SeChangeNotifyPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Bypass traverse checking`
  * **Registry Location**: Stored inside local security database under privilege `SeChangeNotifyPrivilege` set to `*S-1-5-32-554 (Pre-Windows 2000 Compatible Access), *S-1-5-11 (Authenticated Users), *S-1-5-32-544 (Administrators), *S-1-5-20 (NetworkService), *S-1-5-19 (LocalService), *S-1-1-0 (Everyone)`.

---

## Rationale
The `SeChangeNotifyPrivilege` grants the caller the ability to traverse directory trees to access child objects (files and subdirectories) even if the user lacks explicit 'Traverse Folder / Execute File' permissions on parent directories in the path. In addition, this privilege enables applications to register for file system change notifications via APIs such as `ReadDirectoryChangesW`. While enabled broadly on workstations for user convenience, on Domain Controllers and hardened infrastructure, directory navigation paths must be securely bounded.

### 1. Technical Threat Vector & Abuse Mechanics
Allowing broad traversal checking allows users who know the exact name and path of a hidden or deeply nested file to open it directly, bypassing restrictive access controls placed on intermediate folders. While the target file or folder must still allow read access via its own DACL, intermediate directory hiding (e.g., removing traverse rights to prevent discovery of confidential administrative directories) is completely bypassed when this privilege is active. On Domain Controllers, this right must be strictly governed to maintain directory structure confidentiality.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

Baseline standards configure `SeChangeNotifyPrivilege` to `Administrators` (S-1-5-32-544), `Authenticated Users` (S-1-5-11), `Everyone` (S-1-1-0), `Local Service` (S-1-5-19), `Network Service` (S-1-5-20), and `Pre-Windows 2000 Compatible Access` (S-1-5-32-554) to ensure standard application compatibility while preserving core directory notifications. Unauthorized groups must not be added to this allocation.

### 3. MITRE ATT&CK Mapping
* **T1083 - File and Directory Discovery**
* **T1078 - Valid Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Maintaining the standard CIS/Microsoft baseline allocation ensures full compatibility for operating system notifications, file explorer synchronization, and application directory watching. Restricting this right beyond standard baselines can cause extensive application failures, explorer hangings, and broken file sharing sessions. Auditing can be verified through Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Bypass traverse checking`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-554 (Pre-Windows 2000 Compatible Access), *S-1-5-11 (Authenticated Users), *S-1-5-32-544 (Administrators), *S-1-5-20 (NetworkService), *S-1-5-19 (LocalService), *S-1-1-0 (Everyone)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeChangeNotifyPrivilege.ps1](../implementation_scripts/Configure-DcUraSeChangeNotifyPrivilege.ps1)

```powershell
# Configure-DcUraSeChangeNotifyPrivilege.ps1
# Configure-DcUraSeChangeNotifyPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sechangenotifyprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sechangenotifyprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeChangeNotifyPrivilege\s*=") {
        $NewLines += "SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0")
    } else {
        $NewLines += "SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeChangeNotifyPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeChangeNotifyPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeChangeNotifyPrivilegeStatus.ps1
# Get-DcUraSeChangeNotifyPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sechangenotifyprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeChangeNotifyPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0"
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
* **CIS Benchmark**: 2.2.6 (L1) Ensure 'Bypass traverse checking' is set to standard baseline
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
