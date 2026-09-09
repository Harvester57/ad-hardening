# [REQ-PAW-114] Configure User Rights: Deny log on through Remote Desktop Services for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-125](../../08-endpoints/user-rights/configure-ura-sedenyremoteinteractivelogonright.md)).* *(For Domain Controllers, refer to [REQ-DC-121](../../02-domain-controllers/user-rights/configure-ura-sedenyremoteinteractivelogonright.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Deny log on through Remote Desktop Services`
  * **Privilege Constant**: `SeDenyRemoteInteractiveLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyRemoteInteractiveLogonRight` set to `*S-1-5-113 (Local Account), *S-1-5-114 (Local Account and member of Administrators group)`.

---

## Rationale
The `SeDenyRemoteInteractiveLogonRight` explicitly denies designated accounts the ability to establish Remote Desktop Protocol (RDP) sessions (Logon Type 10) on the target system. RDP exposes a full graphical interactive session over TCP port 3389, providing an attacker with interactive desktop capabilities and loading user credentials into memory.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries who compromise local credentials routinely use RDP to pivot interactively across systems. If local administrative accounts or guest accounts are allowed RDP access, attackers can remotely access workstations and servers without leaving network-only traces, hijacking existing sessions or dumping cached credentials. On PAWs and Endpoints, denying remote desktop logon to `Local Account` (S-1-5-113) and `Local account and member of Administrators group` (S-1-5-114) prevents adversaries from using local credentials to log on interactively over RDP.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

On Endpoints and PAWs, configure `SeDenyRemoteInteractiveLogonRight` to include `Local Account` (S-1-5-113), `Local account and member of Administrators group` (S-1-5-114), and `Guests` (S-1-5-32-546). On Domain Controllers, configure to include `Guests` (S-1-5-32-546). This configuration enforces strict administrative tiering and prevents RDP credential abuse.

### 3. MITRE ATT&CK Mapping
* **T1021.001 - Remote Services: Remote Desktop Protocol**
* **T1078.003 - Valid Accounts: Local Accounts**
* **T1550.002 - Use Alternate Authentication Material: Pass the Hash**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Denying RDP access to local accounts requires system administrators to use domain-joined administrative accounts with multifactor authentication or dedicated jump boxes for remote assistance. Local console access via physical keyboard or virtual hypervisor console remains unaffected. Unauthorized RDP connection attempts generate Security Event ID 4625 with Status code `0xC000006E`.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Deny log on through Remote Desktop Services`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-113 (Local Account), *S-1-5-114 (Local Account and member of Administrators group)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1](../implementation_scripts/Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1)

```powershell
# Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1
# Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenyremoteinteractivelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenyremoteinteractivelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyRemoteInteractiveLogonRight\s*=") {
        $NewLines += "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114")
    } else {
        $NewLines += "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1](../audit_scripts/Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1)

```powershell
# Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1
# Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenyremoteinteractivelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-113,*S-1-5-114"
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
* **CIS Benchmark**: 2.2.19 (L1) Ensure 'Deny log on through Remote Desktop Services' includes 'Guests, Local account and member of Administrators group'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
