# [REQ-PAW-099] Configure User Rights: Create global objects for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-105](../../08-endpoints/user-rights/configure-ura-secreateglobalprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Create global objects`
  * **Privilege Constant**: `SeCreateGlobalPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create global objects`
  * **Registry Location**: Stored inside local security database under privilege `SeCreateGlobalPrivilege` set to `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators), *S-1-5-6 (Service)`.

---

## Rationale
The `SeCreateGlobalPrivilege` allows a process to create named kernel and user objects (such as named pipes, shared memory sections, mutexes, and events) in the `\BaseNamedObjects` global namespace accessible across all terminal services sessions and interactive logon sessions. In terminal services and multi-user Windows environments, each interactive session is isolated into a private namespace (`\Sessions\X\BaseNamedObjects`). The global namespace is reserved for system services that must communicate across session boundaries.

### 1. Technical Threat Vector & Abuse Mechanics
If an unprivileged user or low-integrity process obtains `SeCreateGlobalPrivilege`, an adversary can perform object squatting, race-condition hijacking, and cross-session privilege escalation. By pre-creating a named pipe, mutex, or shared memory section with a predictable name in the global namespace before a privileged service initializes, an attacker can intercept communication, inject malicious data into inter-process communication (IPC) streams, or trick a high-integrity service into executing arbitrary shellcode. This privilege is a key prerequisite for session-crossing named pipe impersonation attacks.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544), `LocalService` (S-1-5-19), `NetworkService` (S-1-5-20), and `Service` (S-1-5-6). Standard interactive users, unprivileged domain accounts, and non-administrative applications must never be granted `SeCreateGlobalPrivilege`. Restricting this privilege enforces session isolation and eliminates object collision vulnerabilities.

### 3. MITRE ATT&CK Mapping
* **T1055 - Process Injection**
* **T1068 - Exploitation for Privilege Escalation**
* **T1574 - Hijack Execution Flow**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeCreateGlobalPrivilege` prevents unprivileged processes from colliding with system objects. Legacy client-server desktop applications or multi-user software that utilizes global named pipes for inter-process communication may fail if run by standard users; such applications must be modernized to use session-relative namespaces or secure RPC endpoints. Monitor Security Event ID 4672 and Event ID 4673 for unauthorized global object creation attempts.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Create global objects`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators), *S-1-5-6 (Service)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeCreateGlobalPrivilege.ps1](../implementation_scripts/Configure-PawUraSeCreateGlobalPrivilege.ps1)

```powershell
# Configure-PawUraSeCreateGlobalPrivilege.ps1
# Configure-PawUraSeCreateGlobalPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreateglobalprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreateglobalprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreateGlobalPrivilege\s*=") {
        $NewLines += "SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6")
    } else {
        $NewLines += "SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeCreateGlobalPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeCreateGlobalPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeCreateGlobalPrivilegeStatus.ps1
# Get-PawUraSeCreateGlobalPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreateglobalprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreateGlobalPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
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
* **CIS Benchmark**: 2.2.7 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
