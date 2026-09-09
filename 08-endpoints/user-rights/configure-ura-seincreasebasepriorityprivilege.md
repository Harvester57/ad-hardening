# [REQ-END-112] Configure User Rights: Increase scheduling priority

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Increase scheduling priority`
  * **Privilege Constant**: `SeIncreaseBasePriorityPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Increase scheduling priority`
  * **Registry Location**: Stored inside local security database under privilege `SeIncreaseBasePriorityPrivilege` set to `*S-1-5-32-544 (Administrators), *S-1-5-90-0 (Window Manager Group)`.

---

## Rationale
The `SeIncreaseBasePriorityPrivilege` allows a process to raise the execution priority class of a process or thread via `SetPriorityClass` to `REALTIME_PRIORITY_CLASS`. The Windows kernel thread scheduler gives realtime priority threads preemption authority over virtually all other system threads, including device driver deferred procedure calls (DPCs) and operating system subsystem threads.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary holding `SeIncreaseBasePriorityPrivilege` can execute resource starvation, timing manipulation, and denial-of-service attacks: (1) System Lockup: A malicious realtime priority process consuming 100% CPU cycles starves critical system threads (including mouse/keyboard input handling, network processing, and watchdog timers), completely freezing the computer and requiring a hard reboot; (2) Anti-Malware Evasion: By boosting thread priority, an attacker can outpace asynchronous endpoint detection and response (EDR) inspection routines or induce timing race conditions.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544) and `Window Manager\Window Manager Group` (S-1-5-90-0) if required for DWM rendering. Standard users and background utilities must not have the ability to elevate processes to realtime priority.

### 3. MITRE ATT&CK Mapping
* **T1499 - Endpoint Denial of Service**
* **T1562.001 - Impair Defenses: Disable or Modify Tools**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeIncreaseBasePriorityPrivilege` prevents user-mode processes from inducing thread starvation and kernel lockups. Multimedia software or audio processing suites that request elevated scheduling priority operate effectively within high-priority classes without requiring realtime rights. Auditing is captured via Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Increase scheduling priority`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators), *S-1-5-90-0 (Window Manager Group)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeIncreaseBasePriorityPrivilege.ps1](../implementation_scripts/Configure-UraSeIncreaseBasePriorityPrivilege.ps1)

```powershell
# Configure-UraSeIncreaseBasePriorityPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seincreasebasepriorityprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seincreasebasepriorityprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeIncreaseBasePriorityPrivilege\s*=") {
        $NewLines += "SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0")
    } else {
        $NewLines += "SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeIncreaseBasePriorityPrivilegeStatus.ps1](../audit_scripts/Get-UraSeIncreaseBasePriorityPrivilegeStatus.ps1)

```powershell
# Get-UraSeIncreaseBasePriorityPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seincreasebasepriorityprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeIncreaseBasePriorityPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-544,*S-1-5-90-0"
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
* **CIS Benchmark**: 2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
