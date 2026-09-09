# [REQ-END-123] Configure User Rights: Modify an object label

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Modify an object label`
  * **Privilege Constant**: `SeRelabelPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify an object label`
  * **Registry Location**: Stored inside local security database under privilege `SeRelabelPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeRelabelPrivilege` controls the ability to modify the Mandatory Integrity Control (MIC) label of securable objects via `SetKernelObjectSecurity` or `SetNamedSecurityInfo`. Windows Mandatory Integrity Control defines four primary integrity levels: Low, Medium, High, and System. MIC enforces 'No Write Up' rules, preventing a process running at a lower integrity level from writing to or modifying objects at a higher integrity level.

### 1. Technical Threat Vector & Abuse Mechanics
If an attacker gains access to a process possessing `SeRelabelPrivilege`, they can bypass Mandatory Integrity Control boundaries: (1) Integrity Demotion: An attacker can demote the integrity label of a high-integrity system file, registry key, or process from High/System to Low/Medium. Once demoted, low-integrity processes (such as a compromised web browser sandbox) can overwrite or inject code into the resource; (2) Sandbox Escape: An attacker can elevate the integrity level of malicious files or sockets, neutralizing sandbox isolation.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be strictly configured to `No one` (Empty). No interactive user accounts or standard administrators require manual object label relabeling. Operating system components adjust integrity labels automatically through internal kernel mechanisms.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**
* **T1562.001 - Impair Defenses: Disable or Modify Tools**
* **T1222.001 - File and Directory Permissions Modification: Windows DACL**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Setting `SeRelabelPrivilege` to `No one` preserves Mandatory Integrity Control enforcement without disrupting standard application execution. Standard file and registry creation operations automatically receive the creating process integrity level. Audited under Security Event ID 4704.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Modify an object label`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeRelabelPrivilege.ps1](../implementation_scripts/Configure-UraSeRelabelPrivilege.ps1)

```powershell
# Configure-UraSeRelabelPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_serelabelprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_serelabelprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeRelabelPrivilege\s*=") {
        $NewLines += "SeRelabelPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeRelabelPrivilege = ")
    } else {
        $NewLines += "SeRelabelPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeRelabelPrivilegeStatus.ps1](../audit_scripts/Get-UraSeRelabelPrivilegeStatus.ps1)

```powershell
# Get-UraSeRelabelPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_serelabelprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeRelabelPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.30 (L1) Ensure 'Modify an object label' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
