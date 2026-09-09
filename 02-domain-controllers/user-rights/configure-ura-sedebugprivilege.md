# [REQ-DC-116] Configure User Rights: Debug programs on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-101](../../07-paws/user-rights/configure-ura-sedebugprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-108](../../08-endpoints/user-rights/configure-ura-sedebugprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Debug programs`
  * **Privilege Constant**: `SeDebugPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Debug programs`
  * **Registry Location**: Stored inside local security database under privilege `SeDebugPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeDebugPrivilege` allows a process to attach a debugger to any running process on the system, completely overriding the target process security descriptor and Discretionary Access Control List (DACL). When enabled, calls to `OpenProcess` with permissions such as `PROCESS_ALL_ACCESS` or `PROCESS_VM_READ` succeed even against processes owned by other users or `NT AUTHORITY\SYSTEM`. This privilege is intended strictly for kernel/application developers debugging live processes.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries and post-exploitation frameworks (e.g., Mimikatz, Cobalt Strike, Meterpreter, ProcDump) rely on `SeDebugPrivilege` as the primary mechanism for OS credential theft. By enabling `SeDebugPrivilege`, an attacker can open an unrestricted handle to the Local Security Authority Subsystem Service (`lsass.exe`) and dump process memory to extract: (1) Cleartext passwords cached in WDigest; (2) NTLM password hashes for local and domain accounts; (3) Kerberos Ticket Granting Tickets (TGTs) and session keys; (4) DPAPI master keys. Furthermore, `SeDebugPrivilege` enables process injection into high-integrity services (`svchost.exe`, `csrss.exe`) via `VirtualAllocEx` and `CreateRemoteThread`.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be strictly confined to `Administrators` (S-1-5-32-544) on standard endpoints, Domain Controllers, and PAWs. On PAWs and Tier 0 systems, administrative accounts should only enable this privilege when actively performing emergency system troubleshooting. Standard users, developers (on non-developer workstations), and automated service accounts must never hold `SeDebugPrivilege`.

### 3. MITRE ATT&CK Mapping
* **T1003.001 - OS Credential Dumping: LSASS Memory**
* **T1055 - Process Injection**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeDebugPrivilege` to `Administrators` protects system process memory and prevents unprivileged credential theft. Software developers or diagnostic monitoring agents running as non-administrators may require elevation to debug processes. Security Operations Center (SOC) teams should configure high-severity alerts for Security Event ID 4672 and Event ID 4673 whenever `SeDebugPrivilege` is invoked outside of designated maintenance windows.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Debug programs`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeDebugPrivilege.ps1](../implementation_scripts/Configure-DcUraSeDebugPrivilege.ps1)

```powershell
# Configure-DcUraSeDebugPrivilege.ps1
# Configure-DcUraSeDebugPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedebugprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedebugprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDebugPrivilege\s*=") {
        $NewLines += "SeDebugPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDebugPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeDebugPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeDebugPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeDebugPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeDebugPrivilegeStatus.ps1
# Get-DcUraSeDebugPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedebugprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDebugPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.13 (L1) Ensure 'Debug programs' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
