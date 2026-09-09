# [REQ-DC-108] Configure User Rights: Allow log on locally on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-095](../../07-paws/user-rights/configure-ura-seinteractivelogonright.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-099](../../08-endpoints/user-rights/configure-ura-seinteractivelogonright.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Allow log on locally`
  * **Privilege Constant**: `SeInteractiveLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on locally`
  * **Registry Location**: Stored inside local security database under privilege `SeInteractiveLogonRight` set to `*S-1-5-9 (Enterprise Domain Controllers), *S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeInteractiveLogonRight` determines which security principals are permitted to start an interactive logon session (Logon Type 2) at the physical keyboard, display, or virtual machine console. An interactive logon spawns a graphical user shell (`explorer.exe`) and interactive desktop session.

### 1. Technical Threat Vector & Abuse Mechanics
On Tier 0 systems (Domain Controllers and PAWs), interactive console access must be locked down with extreme rigor: (1) Credential Exposure: When a user logs on interactively, their credentials, Kerberos tickets, and DPAPI keys are loaded into LSASS memory on that machine. If non-administrative users or Tier 1/2 operators log on to a Domain Controller, their credentials are exposed to any compromised service; (2) Attack Surface Expansion: Interactive sessions allow users to launch local tools, browse files, stage exploit payloads, and trigger local kernel vulnerabilities. Standard domain users must never be permitted interactive access to Domain Controllers or PAWs.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Domain Controllers, configure strictly to `Administrators` (S-1-5-32-544) and `Enterprise Domain Controllers` (S-1-5-9). On PAWs, configure strictly to `Administrators` (S-1-5-32-544). On Endpoints, configure to `Administrators` (S-1-5-32-544) and `Users` (S-1-5-32-545) to permit authorized workstation users to log on.

### 3. MITRE ATT&CK Mapping
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1078.003 - Valid Accounts: Local Accounts**
* **T1003.001 - OS Credential Dumping: LSASS Memory**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting interactive logon on Domain Controllers and PAWs enforces clean-source administrative isolation and prevents credential theft. Operators who previously logged on directly to DC consoles to manage users must use Remote Server Administration Tools (RSAT) from dedicated PAWs. Interactive logons generate Security Event ID 4624 (Logon Type 2).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Allow log on locally`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-9 (Enterprise Domain Controllers), *S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeInteractiveLogonRight.ps1](../implementation_scripts/Configure-DcUraSeInteractiveLogonRight.ps1)

```powershell
# Configure-DcUraSeInteractiveLogonRight.ps1
# Configure-DcUraSeInteractiveLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seinteractivelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seinteractivelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeInteractiveLogonRight\s*=") {
        $NewLines += "SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-544")
    } else {
        $NewLines += "SeInteractiveLogonRight = *S-1-5-9,*S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeInteractiveLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeInteractiveLogonRightStatus.ps1)

```powershell
# Get-DcUraSeInteractiveLogonRightStatus.ps1
# Get-DcUraSeInteractiveLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seinteractivelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeInteractiveLogonRight\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-9,*S-1-5-32-544"
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
* **CIS Benchmark**: 2.2.26 (L1) Ensure 'Allow log on locally' is properly restricted per profile
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
