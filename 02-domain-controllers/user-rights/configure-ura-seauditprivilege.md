# [REQ-DC-124] Configure User Rights: Generate security audits on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Generate security audits`
  * **Privilege Constant**: `SeAuditPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Generate security audits`
  * **Registry Location**: Stored inside local security database under privilege `SeAuditPrivilege` set to `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService)`.

---

## Rationale
The `SeAuditPrivilege` allows a process to write synthetic records directly into the Windows Security Event Log (`Security.evtx`) by invoking the Local Security Authority (LSA) and Authz APIs, specifically `AuthzReportSecurityEvent` or `LsaRegisterLogonProcess`. The Windows Security event log is the primary tamper-resistant telemetry source for forensic investigations, compliance audits, and Security Information and Event Management (SIEM) ingest. Access to inject events directly into this log without generating standard OS audit trails represents a critical security hazard.

### 1. Technical Threat Vector & Abuse Mechanics
If an attacker or unprivileged account is granted `SeAuditPrivilege`, they can conduct audit tampering, false-flag generation, and denial-of-service attacks against SIEM pipelines. Adversaries can inject arbitrary synthetic logon/logoff events, privilege use records, or object access events to establish false alibis or mask genuine lateral movement. Furthermore, high-volume event injection can exhaust the maximum log capacity of `Security.evtx`, triggering log retention overwrites or forcing the operating system to shut down if `CrashOnAuditFail` is configured.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

Under secure baselines, `SeAuditPrivilege` must be allocated exclusively to `LocalService` (S-1-5-19) and `NetworkService` (S-1-5-20), which host operating system components that generate specialized audit records. Interactive users, domain administrators, and standard service accounts must never hold this right, as auditing is handled automatically by the Windows kernel and Local Security Authority Subsystem Service (LSASS).

### 3. MITRE ATT&CK Mapping
* **T1562.002 - Impair Defenses: Disable Windows Event Logging**
* **T1070.001 - Indicator Removal: Clear Windows Event Logs**
* **T1078 - Valid Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Confining `SeAuditPrivilege` to `LocalService` and `NetworkService` prevents unauthorized synthetic log creation while preserving standard operating system event auditing. Legacy third-party authentication proxies, RADIUS servers, or custom syslog forwarders that run as domain service accounts may attempt to generate security audits directly; these applications should be reconfigured to write to dedicated Application logs or forward events via standard Windows Event Forwarding (WEF). Security operations teams should track Event ID 4672 and Event ID 4704 to detect unauthorized assignments of `SeAuditPrivilege`.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Generate security audits`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeAuditPrivilege.ps1](../implementation_scripts/Configure-DcUraSeAuditPrivilege.ps1)

```powershell
# Configure-DcUraSeAuditPrivilege.ps1
# Configure-DcUraSeAuditPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seauditprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seauditprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeAuditPrivilege\s*=") {
        $NewLines += "SeAuditPrivilege = *S-1-5-19,*S-1-5-20"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeAuditPrivilege = *S-1-5-19,*S-1-5-20")
    } else {
        $NewLines += "SeAuditPrivilege = *S-1-5-19,*S-1-5-20"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeAuditPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeAuditPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeAuditPrivilegeStatus.ps1
# Get-DcUraSeAuditPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seauditprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeAuditPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-19,*S-1-5-20"
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
* **CIS Benchmark**: 2.2.22 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
