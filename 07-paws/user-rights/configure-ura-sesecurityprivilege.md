# [REQ-PAW-107] Configure User Rights: Manage auditing and security log for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-115](../../08-endpoints/user-rights/configure-ura-sesecurityprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-129](../../02-domain-controllers/user-rights/configure-ura-sesecurityprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Manage auditing and security log`
  * **Privilege Constant**: `SeSecurityPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Manage auditing and security log`
  * **Registry Location**: Stored inside local security database under privilege `SeSecurityPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeSecurityPrivilege` controls access to the Windows Security Event Log (`Security.evtx`) and governs the ability to view, configure, and clear the security log, as well as specify object auditing options (System Access Control Lists - SACLs) on files, registry keys, and directory objects via `ACCESS_SYSTEM_SECURITY`.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary holding `SeSecurityPrivilege` can blind security operations and erase digital forensic evidence: (1) Log Cleansing: The attacker can invoke `ClearEventLog` or run `wevtutil cl Security` to erase all audit records, destroying evidence of privilege escalation, lateral movement, credential dumping, and payload execution; (2) SACL Manipulation: The attacker can strip SACLs from critical files, registry keys, or Active Directory objects, preventing the generation of security event logs when sensitive resources are accessed or modified; (3) Evasion: Bypassing object auditing allows stealthy tampering with protected directory service objects.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). Standard domain users, helpdesk operators, and third-party monitoring agents must not hold `SeSecurityPrivilege`. Security event log forwarding should be configured using Windows Event Forwarding (WEF) running under dedicated network service accounts without granting log management rights.

### 3. MITRE ATT&CK Mapping
* **T1070.001 - Indicator Removal: Clear Windows Event Logs**
* **T1562.002 - Impair Defenses: Disable Windows Event Logging**
* **T1222.001 - File and Directory Permissions Modification: Windows DACL**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeSecurityPrivilege` to `Administrators` protects the integrity of security audit logs. Centralized SIEM forwarders (e.g., Splunk, Microsoft Sentinel, Elastic Agent) that run as dedicated service accounts should be configured to read event logs via membership in the `Event Log Readers` built-in group rather than holding `SeSecurityPrivilege`. Log clearing events generate critical Security Event ID 1102 ('The audit log was cleared').

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Manage auditing and security log`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeSecurityPrivilege.ps1](../implementation_scripts/Configure-PawUraSeSecurityPrivilege.ps1)

```powershell
# Configure-PawUraSeSecurityPrivilege.ps1
# Configure-PawUraSeSecurityPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sesecurityprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sesecurityprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeSecurityPrivilege\s*=") {
        $NewLines += "SeSecurityPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeSecurityPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeSecurityPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeSecurityPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeSecurityPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeSecurityPrivilegeStatus.ps1
# Get-PawUraSeSecurityPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sesecurityprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeSecurityPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.31 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
