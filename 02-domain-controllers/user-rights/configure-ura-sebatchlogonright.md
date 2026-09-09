# [REQ-DC-127] Configure User Rights: Log on as a batch job on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Log on as a batch job`
  * **Privilege Constant**: `SeBatchLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Log on as a batch job`
  * **Registry Location**: Stored inside local security database under privilege `SeBatchLogonRight` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeBatchLogonRight` determines which security principals can authenticate and establish non-interactive batch logon sessions (Logon Type 4). Batch logons are utilized by the Task Scheduler (`taskschd.msc`) and batch queuing subsystems to execute scheduled tasks, maintenance scripts, and background workloads without requiring an interactive desktop session or terminal connection.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries who obtain account credentials exploit `SeBatchLogonRight` to establish persistence and execute command-and-control scripts via scheduled tasks. If standard domain users or unprivileged service accounts possess this right on sensitive servers or Domain Controllers, an attacker with compromised low-level credentials can schedule recurring malicious tasks that execute silently in the background. Furthermore, batch logons create logon sessions that may cache credentials or Kerberos tickets in LSASS memory, exposing them to credential dumping.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Domain Controllers and Tier 0 systems, `SeBatchLogonRight` must be restricted exclusively to `Administrators` (S-1-5-32-544). Standard domain users, guest accounts, and unprivileged identities must be strictly excluded to prevent unauthorized scheduled task creation and non-interactive script execution.

### 3. MITRE ATT&CK Mapping
* **T1053.005 - Scheduled Task/Job: Scheduled Task**
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting batch logon rights prevents non-administrators from executing unattended scheduled tasks. Administrative scripts, enterprise maintenance tasks, and backup schedules that run under dedicated service accounts will require explicit authorization or migration to execute under the `Administrators` group or managed service identities. Monitor Security Event ID 4624 (Logon Type 4) to audit batch logon activity across mission-critical systems.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Log on as a batch job`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeBatchLogonRight.ps1](../implementation_scripts/Configure-DcUraSeBatchLogonRight.ps1)

```powershell
# Configure-DcUraSeBatchLogonRight.ps1
# Configure-DcUraSeBatchLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sebatchlogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sebatchlogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeBatchLogonRight\s*=") {
        $NewLines += "SeBatchLogonRight = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeBatchLogonRight = *S-1-5-32-544")
    } else {
        $NewLines += "SeBatchLogonRight = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeBatchLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeBatchLogonRightStatus.ps1)

```powershell
# Get-DcUraSeBatchLogonRightStatus.ps1
# Get-DcUraSeBatchLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sebatchlogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeBatchLogonRight\s*=\s*(.*)$"
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
* **ANSSI Active Directory Hardening Guide**: ANSSI Active Directory Hardening Guide: R29 (Logon Rights Assignment)
* **CIS Benchmark**: 2.2.29 (L1) Ensure 'Log on as a batch job' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
