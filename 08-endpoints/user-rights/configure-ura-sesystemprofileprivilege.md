# [REQ-END-119] Configure User Rights: Profile system performance

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Profile system performance`
  * **Privilege Constant**: `SeSystemProfilePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile system performance`
  * **Registry Location**: Stored inside local security database under privilege `SeSystemProfilePrivilege` set to `*S-1-5-32-544 (Administrators), *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420 (WdiServiceHost)`.

---

## Rationale
The `SeSystemProfilePrivilege` allows a process to use performance monitoring tools to sample and profile operating system-wide and kernel-level performance via Windows tracing APIs and hardware performance counters.

### 1. Technical Threat Vector & Abuse Mechanics
Kernel profiling permissions expose sensitive system-level telemetry to potential abuse: (1) Kernel Memory Layout Inference: Sampling kernel hardware counters and interrupt timings enables adversaries to infer kernel memory layout, locating un-randomized kernel data structures to defeat Kernel Address Space Layout Randomization (KASLR); (2) Side-Channel Exploits: Analyzing branch execution performance counters facilitates transient execution attacks (Spectre/Meltdown variants) to read kernel memory across privilege boundaries; (3) Sensor Evasion: Profiling security drivers helps attackers discover detection latency windows.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544) and `NT SERVICE\WdiServiceHost` (S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420) where required for built-in diagnostic hosting. Standard users and unprivileged processes must not possess kernel profiling capabilities.

### 3. MITRE ATT&CK Mapping
* **T1057 - Process Discovery**
* **T1055 - Process Injection**
* **T1562 - Impair Defenses**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeSystemProfilePrivilege` prevents unauthorized kernel performance analysis. Administrative monitoring utilities and Windows Performance Analyzer continue to function normally when executed by elevated administrators. Auditing is captured via Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Profile system performance`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators), *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420 (WdiServiceHost)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeSystemProfilePrivilege.ps1](../implementation_scripts/Configure-UraSeSystemProfilePrivilege.ps1)

```powershell
# Configure-UraSeSystemProfilePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sesystemprofileprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sesystemprofileprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeSystemProfilePrivilege\s*=") {
        $NewLines += "SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420")
    } else {
        $NewLines += "SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeSystemProfilePrivilegeStatus.ps1](../audit_scripts/Get-UraSeSystemProfilePrivilegeStatus.ps1)

```powershell
# Get-UraSeSystemProfilePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sesystemprofileprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeSystemProfilePrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420"
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
* **CIS Benchmark**: 2.2.40 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
