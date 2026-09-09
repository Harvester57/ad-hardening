# [REQ-DC-135] Configure User Rights: Take ownership of files or other objects on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-112](../../07-paws/user-rights/configure-ura-setakeownershipprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-122](../../08-endpoints/user-rights/configure-ura-setakeownershipprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Take ownership of files or other objects`
  * **Privilege Constant**: `SeTakeOwnershipPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Take ownership of files or other objects`
  * **Registry Location**: Stored inside local security database under privilege `SeTakeOwnershipPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeTakeOwnershipPrivilege` allows a user to take ownership of any securable object in the operating system (files, directories, registry keys, Active Directory objects, printers, services) by writing the caller's SID into the object security descriptor owner field via `SetNamedSecurityInfo` or `SetSecurityInfo`. The Windows security model grants the owner of an object implicit `WRITE_DAC` authority.

### 1. Technical Threat Vector & Abuse Mechanics
An adversary possessing `SeTakeOwnershipPrivilege` can bypass all Discretionary Access Control Lists (DACLs) on the system: (1) Access Modification: Regardless of whether the current DACL denies access to the attacker, taking ownership grants the attacker implicit authority to rewrite the object's DACL; (2) System Hijacking: The attacker grants themselves `Full Control` over protected system files (e.g., `svchost.exe`, `ntoskrnl.exe`), service executables, or registry keys under `HKLM\SYSTEM`, enabling immediate payload insertion and privilege escalation; (3) Active Directory Abuse: Taking ownership of sensitive directory objects allows an attacker to reset administrative passwords or inject malicious ACEs.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). No standard users, guest accounts, or service accounts must be granted ownership takeover authority.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**
* **T1222.001 - File and Directory Permissions Modification: Windows DACL**
* **T1574 - Hijack Execution Flow**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeTakeOwnershipPrivilege` to `Administrators` ensures objects remain protected by their established security descriptors. Administrative personnel retain the capability to take ownership of orphaned resources when managing file systems. Ownership changes generate Security Event ID 4674 and Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Take ownership of files or other objects`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeTakeOwnershipPrivilege.ps1](../implementation_scripts/Configure-DcUraSeTakeOwnershipPrivilege.ps1)

```powershell
# Configure-DcUraSeTakeOwnershipPrivilege.ps1
# Configure-DcUraSeTakeOwnershipPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setakeownershipprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setakeownershipprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTakeOwnershipPrivilege\s*=") {
        $NewLines += "SeTakeOwnershipPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTakeOwnershipPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeTakeOwnershipPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeTakeOwnershipPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeTakeOwnershipPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeTakeOwnershipPrivilegeStatus.ps1
# Get-DcUraSeTakeOwnershipPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setakeownershipprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTakeOwnershipPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.41 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
