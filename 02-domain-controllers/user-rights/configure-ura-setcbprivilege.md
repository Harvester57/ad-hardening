# [REQ-DC-105] Configure User Rights: Act as part of the operating system on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-094](../../07-paws/user-rights/configure-ura-setcbprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-098](../../08-endpoints/user-rights/configure-ura-setcbprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Act as part of the operating system`
  * **Privilege Constant**: `SeTcbPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system`
  * **Registry Location**: Stored inside local security database under privilege `SeTcbPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeTcbPrivilege` identifies its holder as part of the Trusted Computer Base (TCB)—the core inner ring of the operating system. A process possessing this privilege can register as a trusted logon process with the Local Security Authority via `LsaRegisterLogonProcess` and invoke `LsaLogonUser` to create an arbitrary, fully authenticated access token for any user without knowing the user's password or requiring credentials.

### 1. Technical Threat Vector & Abuse Mechanics
Possession of `SeTcbPrivilege` by any user or third-party process represents an immediate, complete compromise of the operating system: (1) Universal Token Forgery: An attacker can call `LsaLogonUser` to request an elevated token for `NT AUTHORITY\SYSTEM` or any Domain Administrator account, bypassing all authentication safeguards; (2) LSA Impersonation: The attacker can interact directly with LSA authentication packages, intercepting plain-text credentials and injecting rogue security support providers (SSPs); (3) Bypassing Security Auditing: TCB processes can suppress audit logging and bypass Mandatory Integrity Control checks.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be strictly configured to `No one` (Empty). Operating system components that require TCB authority (such as `lsass.exe`) run under internal system contexts and do not require user-level assignment of `SeTcbPrivilege`. No human user account, administrative identity, or third-party service account should ever hold this right.

### 3. MITRE ATT&CK Mapping
* **T1134.001 - Access Token Manipulation: Token Impersonation/Theft**
* **T1078 - Valid Accounts**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Configuring `SeTcbPrivilege` to `No one` aligns with Microsoft Security Baselines and CIS Benchmarks and introduces zero operational disruption. No legitimate modern enterprise application requires assignment of this privilege. Any assignment or use of `SeTcbPrivilege` triggers immediate high-severity security alerts (Security Event ID 4704).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Act as part of the operating system`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeTcbPrivilege.ps1](../implementation_scripts/Configure-DcUraSeTcbPrivilege.ps1)

```powershell
# Configure-DcUraSeTcbPrivilege.ps1
# Configure-DcUraSeTcbPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setcbprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setcbprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTcbPrivilege\s*=") {
        $NewLines += "SeTcbPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTcbPrivilege = ")
    } else {
        $NewLines += "SeTcbPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeTcbPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeTcbPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeTcbPrivilegeStatus.ps1
# Get-DcUraSeTcbPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setcbprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTcbPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.5 (L1) Ensure 'Act as part of the operating system' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
