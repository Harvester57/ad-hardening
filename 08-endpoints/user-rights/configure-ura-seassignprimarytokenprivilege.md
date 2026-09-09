# [REQ-END-120] Configure User Rights: Replace a process level token

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Replace a process-level token`
  * **Privilege Constant**: `SeAssignPrimaryTokenPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Replace a process level token`
  * **Registry Location**: Stored inside local security database under privilege `SeAssignPrimaryTokenPrivilege` set to `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService)`.

---

## Rationale
The `SeAssignPrimaryTokenPrivilege` allows a process to assign a primary security access token to a newly initialized process via APIs such as `CreateProcessAsUser` or `SetInformationJobObject`. In the Windows NT security architecture, every process runs under a primary token that defines its user SID, group memberships, privileges, and Mandatory Integrity Control (MIC) level. Under normal conditions, child processes automatically inherit a duplicate of the parent process primary token. When a process holds `SeAssignPrimaryTokenPrivilege`, it can substitute an arbitrary primary token obtained from another session, service, or authentication handshake, effectively launching programs under the security context of any arbitrary user or the local SYSTEM account.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries and local privilege escalation toolkits abuse `SeAssignPrimaryTokenPrivilege` to convert token handles obtained through impersonation, named pipe hijacking, or COM reflection into primary process tokens. If an unprivileged user or compromised service account possesses this right, they can bypass token impersonation restrictions (which prevent impersonation tokens from crossing session boundaries or spawning interactive processes) and spawn a command shell or malicious payload directly as `NT AUTHORITY\SYSTEM`. This privilege is historically targeted in local privilege escalation exploits where attackers leverage services running under virtual or custom service accounts to gain complete system takeover.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

By default, Windows restricts `SeAssignPrimaryTokenPrivilege` exclusively to `LocalService` (S-1-5-19) and `NetworkService` (S-1-5-20) accounts, which are designed to launch helper host processes (such as `svchost.exe` instances). No interactive user accounts, standard administrators, or third-party service principals require this right. Confining this privilege strictly to built-in system service identities ensures that compromised user processes cannot substitute access tokens to spawn elevated child processes.

### 3. MITRE ATT&CK Mapping
* **T1134.001 - Access Token Manipulation: Token Impersonation/Theft**
* **T1068 - Exploitation for Privilege Escalation**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeAssignPrimaryTokenPrivilege` to `LocalService` and `NetworkService` aligns with Microsoft default baselines and does not disrupt standard Windows desktop applications or enterprise client software. Certain legacy server management agents, custom middle-tier transaction servers (e.g., COM+ applications running under domain identities), or third-party process monitors may attempt to request this right; such applications should be updated to execute under managed virtual service accounts or modern service hosting architectures. Administrators should monitor Security Event ID 4672 (Special privileges assigned to new logon) and Event ID 4673 (Sensitive Privilege Use) to audit token replacement invocations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Replace a process-level token`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeAssignPrimaryTokenPrivilege.ps1](../implementation_scripts/Configure-UraSeAssignPrimaryTokenPrivilege.ps1)

```powershell
# Configure-UraSeAssignPrimaryTokenPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seassignprimarytokenprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seassignprimarytokenprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeAssignPrimaryTokenPrivilege\s*=") {
        $NewLines += "SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20")
    } else {
        $NewLines += "SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeAssignPrimaryTokenPrivilegeStatus.ps1](../audit_scripts/Get-UraSeAssignPrimaryTokenPrivilegeStatus.ps1)

```powershell
# Get-UraSeAssignPrimaryTokenPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seassignprimarytokenprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeAssignPrimaryTokenPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.37 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
