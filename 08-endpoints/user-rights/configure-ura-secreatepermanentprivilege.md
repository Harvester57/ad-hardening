# [REQ-END-106] Configure User Rights: Create permanent shared objects

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-100](../../07-paws/user-rights/configure-ura-secreatepermanentprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-115](../../02-domain-controllers/user-rights/configure-ura-secreatepermanentprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Create permanent shared objects`
  * **Privilege Constant**: `SeCreatePermanentPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create permanent shared objects`
  * **Registry Location**: Stored inside local security database under privilege `SeCreatePermanentPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeCreatePermanentPrivilege` allows a process to create permanent object directory objects in the Windows Object Manager namespace (`\DirectoryObject`) via APIs like `NtCreateDirectoryObject`. Unlike standard kernel objects which are automatically destroyed when their last handle is closed, permanent objects persist in the object manager namespace across process terminations until explicitly unlinked or until system reboot.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries can exploit `SeCreatePermanentPrivilege` to achieve stealthy persistence, object squatting, and driver manipulation. By inserting permanent directory entries into system namespaces (such as `\KnownDlls`, `\Device`, or `\Driver`), an attacker can divert DLL resolution paths, hijack device object handles, or trick kernel components into interacting with rogue objects. This privilege provides ring-3 processes with an avenue to tamper with kernel-level object lifecycle management.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

Under rigorous security baselines, `SeCreatePermanentPrivilege` must be set to `No one` (Empty). No user account, administrative identity, or standard service principal requires this privilege in modern Windows environments. Ensuring this privilege is unassigned eliminates permanent object creation risks across the entire fleet.

### 3. MITRE ATT&CK Mapping
* **T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking**
* **T1543 - Create or Modify System Process**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Setting `SeCreatePermanentPrivilege` to `No one` aligns with Microsoft Security Baseline and CIS Benchmarks and introduces no operational degradation. Operating system components that manage permanent objects operate at kernel level and do not depend on user-level privilege assignments. Any attempt to assign or use this privilege triggers Security Event ID 4704 and Event ID 4673.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Create permanent shared objects`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeCreatePermanentPrivilege.ps1](../implementation_scripts/Configure-UraSeCreatePermanentPrivilege.ps1)

```powershell
# Configure-UraSeCreatePermanentPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreatepermanentprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreatepermanentprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreatePermanentPrivilege\s*=") {
        $NewLines += "SeCreatePermanentPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreatePermanentPrivilege = ")
    } else {
        $NewLines += "SeCreatePermanentPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeCreatePermanentPrivilegeStatus.ps1](../audit_scripts/Get-UraSeCreatePermanentPrivilegeStatus.ps1)

```powershell
# Get-UraSeCreatePermanentPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreatepermanentprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreatePermanentPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = ""
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
* **CIS Benchmark**: 2.2.9 (L1) Ensure 'Create permanent shared objects' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
