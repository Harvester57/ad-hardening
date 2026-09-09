# [REQ-DC-131] Configure User Rights: Profile single process on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-110](../../07-paws/user-rights/configure-ura-seprofilesingleprocessprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-118](../../08-endpoints/user-rights/configure-ura-seprofilesingleprocessprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Profile single process`
  * **Privilege Constant**: `SeProfileSingleProcessPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Profile single process`
  * **Registry Location**: Stored inside local security database under privilege `SeProfileSingleProcessPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeProfileSingleProcessPrivilege` allows a process to monitor and profile the performance and execution metrics of non-system processes using Windows performance sampling APIs. Profiling tools monitor instruction execution rates, thread context switches, memory cache behavior, and execution sampling.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary who obtains profiling privileges can perform sophisticated reverse engineering, side-channel analysis, and exploit development: (1) Memory Layout De-randomization: By profiling process memory and execution timings, an attacker can deduce memory layouts and defeat Address Space Layout Randomization (ASLR); (2) Side-Channel Cryptographic Attacks: Profiling cache hits/misses and instruction timings can expose cryptographic key material processed in co-located processes; (3) Security Software Tampering: Attackers analyze EDR sensor thread behavior to identify blind spots or execution hooks.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). Standard users, interactive workstation operators, and general service accounts must not have process profiling capabilities.

### 3. MITRE ATT&CK Mapping
* **T1057 - Process Discovery**
* **T1055 - Process Injection**
* **T1562 - Impair Defenses**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeProfileSingleProcessPrivilege` to `Administrators` prevents unauthorized thread profiling without impacting standard application performance. Developers using standalone profiling tools (such as Visual Studio Profiler) must elevate to administrative context. Auditing is captured under Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Profile single process`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeProfileSingleProcessPrivilege.ps1](../implementation_scripts/Configure-DcUraSeProfileSingleProcessPrivilege.ps1)

```powershell
# Configure-DcUraSeProfileSingleProcessPrivilege.ps1
# Configure-DcUraSeProfileSingleProcessPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seprofilesingleprocessprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seprofilesingleprocessprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeProfileSingleProcessPrivilege\s*=") {
        $NewLines += "SeProfileSingleProcessPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeProfileSingleProcessPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeProfileSingleProcessPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeProfileSingleProcessPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeProfileSingleProcessPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeProfileSingleProcessPrivilegeStatus.ps1
# Get-DcUraSeProfileSingleProcessPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seprofilesingleprocessprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeProfileSingleProcessPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
