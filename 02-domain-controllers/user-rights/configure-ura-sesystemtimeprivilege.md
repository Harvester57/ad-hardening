# [REQ-DC-112] Configure User Rights: Change the system time on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-101](../../08-endpoints/user-rights/configure-ura-sesystemtimeprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Change the system time`
  * **Privilege Constant**: `SeSystemtimePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Change the system time`
  * **Registry Location**: Stored inside local security database under privilege `SeSystemtimePrivilege` set to `*S-1-5-32-544 (Administrators), *S-1-5-19 (LocalService)`.

---

## Rationale
The `SeSystemtimePrivilege` allows a security principal to adjust the internal hardware clock and system time of the computer via Win32 APIs `SetSystemTime` or `SetLocalTime`. Accurate time synchronization is foundational to the Windows distributed security architecture.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries exploit system time alteration to defeat cryptographic protocols, authentication mechanisms, and forensic logging: (1) Kerberos Authentication Subversion: Kerberos tickets have strict timestamp validity windows (default 5-minute allowable skew). Tampering with system time can trigger ticket replay attacks, force ticket invalidation, or induce authentication bypasses; (2) Timestomping and Anti-Forensics: Modifying system time corrupts log event timestamps, confusing SIEM correlation pipelines, incident timelines, and forensic evidence collection; (3) Bypassing Security Policies: Time manipulation can prematurely expire smart card certificates, bypass account lockout cooldowns, or invalidate password age policies.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Endpoints and Domain Controllers, `SeSystemtimePrivilege` must be restricted exclusively to `Administrators` (S-1-5-32-544) and `LocalService` (S-1-5-19) (which hosts the Windows Time service `W32Time`). Standard users and unprivileged applications must never possess system time modification rights.

### 3. MITRE ATT&CK Mapping
* **T1558 - Steal or Forge Kerberos Tickets**
* **T1070.006 - Indicator Removal: Timestomp**
* **T1562 - Impair Defenses**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeSystemtimePrivilege` ensures time integrity across domain workstations and servers. Time synchronization occurs automatically via the Windows Time service against Domain Controllers (NTP). Manual clock adjustments by administrators are logged under Security Event ID 4616 ('The system time was changed').

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Change the system time`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators), *S-1-5-19 (LocalService)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeSystemtimePrivilege.ps1](../implementation_scripts/Configure-DcUraSeSystemtimePrivilege.ps1)

```powershell
# Configure-DcUraSeSystemtimePrivilege.ps1
# Configure-DcUraSeSystemtimePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sesystemtimeprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sesystemtimeprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeSystemtimePrivilege\s*=") {
        $NewLines += "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19")
    } else {
        $NewLines += "SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeSystemtimePrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeSystemtimePrivilegeStatus.ps1)

```powershell
# Get-DcUraSeSystemtimePrivilegeStatus.ps1
# Get-DcUraSeSystemtimePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sesystemtimeprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeSystemtimePrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-544,*S-1-5-19"
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
* **CIS Benchmark**: 2.2.12 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
