# [REQ-PAW-093] Configure User Rights: Access this computer from the network for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-097](../../08-endpoints/user-rights/configure-ura-senetworklogonright.md)).* *(For Domain Controllers, refer to [REQ-DC-104](../../02-domain-controllers/user-rights/configure-ura-senetworklogonright.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Access this computer from the network`
  * **Privilege Constant**: `SeNetworkLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access this computer from the network`
  * **Registry Location**: Stored inside local security database under privilege `SeNetworkLogonRight` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeNetworkLogonRight` determines which security principals are permitted to authenticate and establish network logon sessions (Logon Type 3) across the network over protocols like SMB, RPC, WMI, WinRM, and LDAP. Network logons authenticate users without creating an interactive desktop shell, enabling file share access, remote management, and inter-system synchronization.

### 1. Technical Threat Vector & Abuse Mechanics
Allowing broad network logon rights opens the system to unauthorized remote inspection, password spraying, and lateral movement: (1) On PAWs: Privileged Access Workstations must be isolated clean sources. Allowing incoming network connections permits an attacker to connect to a PAW over SMB or RPC, scan for listening services, and attempt credential relaying. PAWs must restrict network logon strictly to `Administrators` (S-1-5-32-544); (2) On Domain Controllers: Network logons must allow domain communication for `Enterprise Domain Controllers` (S-1-5-9) and `Authenticated Users` (S-1-5-11), while excluding untrusted and anonymous callers; (3) On Endpoints: Workstations should permit network logons to `Administrators` and `Authenticated Users` while denying local accounts via deny rules.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

On PAWs, configure strictly to `Administrators` (S-1-5-32-544). On Domain Controllers, configure to `Administrators` (S-1-5-32-544), `Authenticated Users` (S-1-5-11), and `Enterprise Domain Controllers` (S-1-5-9). On Endpoints, configure to `Administrators` (S-1-5-32-544) and `Authenticated Users` (S-1-5-11). Untrusted groups like `Everyone` or `Guests` must never be granted network access.

### 3. MITRE ATT&CK Mapping
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**
* **T1021.006 - Remote Services: Windows Remote Management**
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Enforcing proper network logon boundaries isolates administrative workstations while enabling essential domain authentication. Restricting PAWs to Administrators blocks unauthenticated or non-admin network probes. Network logons are audited under Security Event ID 4624 (Logon Type 3).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Access this computer from the network`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeNetworkLogonRight.ps1](../implementation_scripts/Configure-PawUraSeNetworkLogonRight.ps1)

```powershell
# Configure-PawUraSeNetworkLogonRight.ps1
# Configure-PawUraSeNetworkLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_senetworklogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_senetworklogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeNetworkLogonRight\s*=") {
        $NewLines += "SeNetworkLogonRight = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeNetworkLogonRight = *S-1-5-32-544")
    } else {
        $NewLines += "SeNetworkLogonRight = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeNetworkLogonRightStatus.ps1](../audit_scripts/Get-PawUraSeNetworkLogonRightStatus.ps1)

```powershell
# Get-PawUraSeNetworkLogonRightStatus.ps1
# Get-PawUraSeNetworkLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_senetworklogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeNetworkLogonRight\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.2 (L1) Ensure 'Access this computer from the network' is restricted per baseline
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
