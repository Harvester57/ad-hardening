# [REQ-PAW-098] Configure User Rights: Create a token object for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-104](../../08-endpoints/user-rights/configure-ura-secreatetokenprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-114](../../02-domain-controllers/user-rights/configure-ura-secreatetokenprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Create a token object`
  * **Privilege Constant**: `SeCreateTokenPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a token object`
  * **Registry Location**: Stored inside local security database under privilege `SeCreateTokenPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeCreateTokenPrivilege` allows a process to invoke the native API `NtCreateToken` to forge an arbitrary Windows primary or impersonation access token from scratch. An access token defines an entity's complete security context, including User SID, Group SIDs, Privileges, Default DACL, Token Type, and Mandatory Integrity Level. Normally, tokens are manufactured exclusively by the Local Security Authority Subsystem Service (`lsass.exe`) following successful authentication.

### 1. Technical Threat Vector & Abuse Mechanics
A process possessing `SeCreateTokenPrivilege` holds absolute, god-mode authority over the local operating system and potentially the entire Active Directory domain. By calling `NtCreateToken`, an attacker can synthesize an access token containing: (1) The `NT AUTHORITY\SYSTEM` SID (S-1-5-18) or `Administrators` SID (S-1-5-32-544); (2) The `Domain Admins` (S-1-5-21-...-512) or `Enterprise Admins` (S-1-5-21-...-519) SIDs; (3) Every single privilege enabled (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeLoadDriverPrivilege`, etc.); (4) System integrity level (S-1-16-16384). The attacker can then impersonate this forged token via `SetThreadToken` or spawn processes via `CreateProcessAsUser`, instantly bypassing all security controls.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

This user right must be strictly set to `No one` (Empty). No user account, administrative identity, or third-party service account should ever be granted `SeCreateTokenPrivilege`. LSASS operates as a trusted operating system component and does not require this privilege to be granted via user rights assignment.

### 3. MITRE ATT&CK Mapping
* **T1134.001 - Access Token Manipulation: Token Impersonation/Theft**
* **T1078 - Valid Accounts**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Setting `SeCreateTokenPrivilege` to `No one` introduces no operational disruptions. No standard Windows service or commercial enterprise software requires user-level allocation of this privilege. Any appearance of `SeCreateTokenPrivilege` in audit reports indicates extreme misconfiguration or active malicious compromise (Security Event ID 4704).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Create a token object`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeCreateTokenPrivilege.ps1](../implementation_scripts/Configure-PawUraSeCreateTokenPrivilege.ps1)

```powershell
# Configure-PawUraSeCreateTokenPrivilege.ps1
# Configure-PawUraSeCreateTokenPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreatetokenprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreatetokenprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreateTokenPrivilege\s*=") {
        $NewLines += "SeCreateTokenPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreateTokenPrivilege = ")
    } else {
        $NewLines += "SeCreateTokenPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeCreateTokenPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeCreateTokenPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeCreateTokenPrivilegeStatus.ps1
# Get-PawUraSeCreateTokenPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreatetokenprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreateTokenPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = ""
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
* **CIS Benchmark**: 2.2.10 (L1) Ensure 'Create a token object' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
