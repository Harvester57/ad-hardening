# [REQ-END-102] Configure User Rights: Change the time zone

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Change the time zone`
  * **Privilege Constant**: `SeTimeZonePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the time zone`
  * **Registry Location**: Stored inside local security database under privilege `SeTimeZonePrivilege` set to `*S-1-5-32-544 (Administrators), *S-1-5-19 (LocalService), *S-1-5-32-545 (Users)`.

---

## Rationale
The `SeTimeZonePrivilege` controls the capability to change the system local time zone setting via `SetTimeZoneInformation`. While changing the time zone does not alter the underlying UTC hardware clock, it alters the local display time and timestamp calculations across the operating system.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries manipulate time zones to create forensic confusion and obfuscate event timelines: (1) Forensic Timeline Distortion: Tampering with local time zones confounds manual log analysis, incident response triage, and SIEM correlation engines that parse local timestamps rather than UTC; (2) Scheduled Task Disruption: Shifting time zones can alter the execution timing of scheduled maintenance tasks or backup windows; (3) User Confusion: Altering the time zone changes the desktop clock presentation, potentially causing user distraction.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

Under hardened baselines, `SeTimeZonePrivilege` must be restricted to `Administrators` (S-1-5-32-544), `LocalService` (S-1-5-19), and `Users` (S-1-5-32-545) where travel mobility is required, or strictly `Administrators` and `LocalService` on hardened corporate endpoints. Restricting time zone adjustments prevents unauthorized temporal disruption.

### 3. MITRE ATT&CK Mapping
* **T1070.006 - Indicator Removal: Timestomp**
* **T1562 - Impair Defenses**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting time zone modifications ensures enterprise log consistency. Mobile laptop users who travel across time zones may require automated time zone detection via Location Services rather than manual configuration. Auditing is captured under Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Change the time zone`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators), *S-1-5-19 (LocalService), *S-1-5-32-545 (Users)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeTimeZonePrivilege.ps1](../implementation_scripts/Configure-UraSeTimeZonePrivilege.ps1)

```powershell
# Configure-UraSeTimeZonePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setimezoneprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setimezoneprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTimeZonePrivilege\s*=") {
        $NewLines += "SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545")
    } else {
        $NewLines += "SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeTimeZonePrivilegeStatus.ps1](../audit_scripts/Get-UraSeTimeZonePrivilegeStatus.ps1)

```powershell
# Get-UraSeTimeZonePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setimezoneprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTimeZonePrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-544,*S-1-5-19,*S-1-5-32-545"
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
* **CIS Benchmark**: 2.2.14 (L1) Ensure 'Change the time zone' is properly restricted per baseline
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
