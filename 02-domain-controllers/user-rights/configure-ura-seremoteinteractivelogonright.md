# [REQ-DC-109] Configure User Rights: Allow log on through Remote Desktop Services on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Allow log on through Remote Desktop Services`
  * **Privilege Constant**: `SeRemoteInteractiveLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Allow log on through Remote Desktop Services`
  * **Registry Location**: Stored inside local security database under privilege `SeRemoteInteractiveLogonRight` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeRemoteInteractiveLogonRight` determines which security principals are permitted to establish interactive Remote Desktop Protocol (RDP) sessions (Logon Type 10) on the target host. RDP provides full remote graphical desktop access, loading interactive user credentials into LSASS memory.

### 1. Technical Threat Vector & Abuse Mechanics
Unrestricted RDP logon permissions create severe credential exposure and remote management risks: (1) On Domain Controllers: Permitting non-administrators or Tier 1/2 operators to establish RDP sessions to Domain Controllers exposes sensitive administrative sessions to interception, session hijacking (`tscon`), and credential harvesting; (2) Ransomware Lateral Movement: Attackers who compromise user credentials routinely use RDP to spread across the network, manually deploying payloads and altering configurations; (3) Console Hijacking: RDP sessions remain active or disconnected in memory, providing opportunities for session riding.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Domain Controllers, configure strictly to `Administrators` (S-1-5-32-544). On PAWs and Endpoints, RDP access should be strictly governed, with local accounts denied via `SeDenyRemoteInteractiveLogonRight`. Non-administrative domain accounts must never be permitted RDP access to Domain Controllers.

### 3. MITRE ATT&CK Mapping
* **T1021.001 - Remote Services: Remote Desktop Protocol**
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting RDP access on Domain Controllers ensures only authorized Domain Administrators can initiate remote desktop management sessions. Helpdesk staff and non-Tier 0 administrators must use RSAT tools installed on dedicated PAWs rather than logging directly into DC desktops. Remote desktop logons generate Security Event ID 4624 (Logon Type 10).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Allow log on through Remote Desktop Services`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeRemoteInteractiveLogonRight.ps1](../implementation_scripts/Configure-DcUraSeRemoteInteractiveLogonRight.ps1)

```powershell
# Configure-DcUraSeRemoteInteractiveLogonRight.ps1
# Configure-DcUraSeRemoteInteractiveLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seremoteinteractivelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seremoteinteractivelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeRemoteInteractiveLogonRight\s*=") {
        $NewLines += "SeRemoteInteractiveLogonRight = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeRemoteInteractiveLogonRight = *S-1-5-32-544")
    } else {
        $NewLines += "SeRemoteInteractiveLogonRight = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeRemoteInteractiveLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeRemoteInteractiveLogonRightStatus.ps1)

```powershell
# Get-DcUraSeRemoteInteractiveLogonRightStatus.ps1
# Get-DcUraSeRemoteInteractiveLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seremoteinteractivelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeRemoteInteractiveLogonRight\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.3 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DCs)
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
