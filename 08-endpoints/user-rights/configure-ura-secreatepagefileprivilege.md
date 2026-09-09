# [REQ-END-103] Configure User Rights: Create a pagefile

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-097](../../07-paws/user-rights/configure-ura-secreatepagefileprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-113](../../02-domain-controllers/user-rights/configure-ura-secreatepagefileprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Create a pagefile`
  * **Privilege Constant**: `SeCreatePagefilePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile`
  * **Registry Location**: Stored inside local security database under privilege `SeCreatePagefilePrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeCreatePagefilePrivilege` allows a process to create, delete, and modify the parameters and allocation sizes of system paging files (`pagefile.sys`) via the `NtCreatePagingFile` API. The Windows virtual memory manager uses paging files as secondary backing storage for memory pages that are not backed by files. Paging files contain sensitive plaintext data, including process heap allocations, cached authentication tokens, cryptographic keys, and unencrypted file contents.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary with `SeCreatePagefilePrivilege` can cause severe denial of service, manipulate virtual memory backing, or exfiltrate sensitive memory contents: (1) Denial of Service: An attacker can shrink or eliminate paging files, causing memory exhaustion and kernel panics (BSOD) when RAM commitments exceed physical limits; (2) Offline Extraction: An attacker can create a new paging file on an unencrypted removable disk or secondary volume, deliberately forcing sensitive kernel and process memory structures to be written to media under attacker control; (3) Storage Exhaustion: Rapidly creating massive paging files can exhaust disk capacity, disrupting critical services.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This user right must be strictly limited to `Administrators` (S-1-5-32-544). Paging file sizing and placement is an administrative configuration task managed during system deployment and baseline configuration; no standard user or third-party service account has any legitimate need for this privilege.

### 3. MITRE ATT&CK Mapping
* **T1499 - Endpoint Denial of Service**
* **T1003 - OS Credential Dumping**
* **T1005 - Data from Local System**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeCreatePagefilePrivilege` to `Administrators` has zero negative impact on standard applications, enterprise workloads, or user desktop experiences. Paging file management remains fully functional for operating system administrators. Security Event ID 4672 audits administrative sessions holding this privilege upon logon.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Create a pagefile`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeCreatePagefilePrivilege.ps1](../implementation_scripts/Configure-UraSeCreatePagefilePrivilege.ps1)

```powershell
# Configure-UraSeCreatePagefilePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreatepagefileprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreatepagefileprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreatePagefilePrivilege\s*=") {
        $NewLines += "SeCreatePagefilePrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreatePagefilePrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeCreatePagefilePrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeCreatePagefilePrivilegeStatus.ps1](../audit_scripts/Get-UraSeCreatePagefilePrivilegeStatus.ps1)

```powershell
# Get-UraSeCreatePagefilePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreatepagefileprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreatePagefilePrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.8 (L1) Ensure 'Create a pagefile' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
