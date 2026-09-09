# [REQ-END-096] Configure User Rights: Access Credential Manager as a trusted caller

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-092](../../07-paws/user-rights/configure-ura-setrustedcredmanaccessprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Access Credential Manager as a trusted caller`
  * **Privilege Constant**: `SeTrustedCredManAccessPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller`
  * **Registry Location**: Stored inside local security database under privilege `SeTrustedCredManAccessPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeTrustedCredManAccessPrivilege` allows a process to access the Windows Credential Manager as a trusted caller via internal Credential Manager APIs. The Credential Manager securely stores user domain credentials, web passwords, and certificate secrets used for network authentication.

### 1. Technical Threat Vector & Abuse Mechanics
This privilege is reserved exclusively for specialized internal operating system components: (1) Credential Harvesting: If granted to a user account or unprivileged process, an attacker can directly query the Credential Manager to harvest stored domain credentials, smart card PINs, and single sign-on (SSO) tokens; (2) Credential Injection: An attacker could inject fraudulent credentials into Credential Manager to intercept authentication workflows or redirect network requests.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This user right must be strictly set to `No one` (Empty). Microsoft operating system components interact with Credential Manager using internal system mechanisms and do not require user-level assignment of this privilege. Ensuring this privilege is unassigned guarantees that Credential Manager secrets cannot be queried via user-level trusted caller semantics.

### 3. MITRE ATT&CK Mapping
* **T1555.004 - Credentials from Password Stores: Windows Credential Manager**
* **T1003 - OS Credential Dumping**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Setting `SeTrustedCredManAccessPrivilege` to `No one` introduces zero operational impact. Standard Credential Manager storage and retrieval by users and web browsers continues to operate through normal user-level APIs without requiring trusted caller status. Audited via Security Event ID 4704.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Access Credential Manager as a trusted caller`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeTrustedCredManAccessPrivilege.ps1](../implementation_scripts/Configure-UraSeTrustedCredManAccessPrivilege.ps1)

```powershell
# Configure-UraSeTrustedCredManAccessPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setrustedcredmanaccessprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setrustedcredmanaccessprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTrustedCredManAccessPrivilege\s*=") {
        $NewLines += "SeTrustedCredManAccessPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTrustedCredManAccessPrivilege = ")
    } else {
        $NewLines += "SeTrustedCredManAccessPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeTrustedCredManAccessPrivilegeStatus.ps1](../audit_scripts/Get-UraSeTrustedCredManAccessPrivilegeStatus.ps1)

```powershell
# Get-UraSeTrustedCredManAccessPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setrustedcredmanaccessprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTrustedCredManAccessPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
