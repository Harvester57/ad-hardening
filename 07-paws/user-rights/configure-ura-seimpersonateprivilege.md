# [REQ-PAW-104] Configure User Rights: Impersonate a client after authentication for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-111](../../08-endpoints/user-rights/configure-ura-seimpersonateprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Impersonate a client after authentication`
  * **Privilege Constant**: `SeImpersonatePrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Impersonate a client after authentication`
  * **Registry Location**: Stored inside local security database under privilege `SeImpersonatePrivilege` set to `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators), *S-1-5-6 (Service)`.

---

## Rationale
The `SeImpersonatePrivilege` grants a program the ability to impersonate a client that has connected to its local RPC interfaces, named pipes, or COM servers via `ImpersonateNamedPipeClient`, `CoImpersonateClient`, or `RpcImpersonateClient`. Impersonation allows a server process to temporarily run in the security context of the calling client to verify access permissions.

### 1. Technical Threat Vector & Abuse Mechanics
This privilege is the critical execution prerequisite for the entire class of 'Potato' local privilege escalation exploits (RottenPotato, JuicyPotato, PrintSpoofer, RoguePotato, SweetPotato, GodPotato). When an attacker gains code execution under a service account (such as `IIS APPPOOL\DefaultAppPool`, `MSSQLSERVER`, or custom services holding this privilege), the attacker forces a high-privilege service (running as `NT AUTHORITY\SYSTEM`) to authenticate to an attacker-controlled named pipe or RPC endpoint (e.g., via the Print Spooler `RpcRemoteFindFirstPrinterChangeNotificationEx` or COM DCOM activations). The attacker's process then calls `ImpersonateNamedPipeClient`, captures the SYSTEM token, and spawns a command shell as `SYSTEM`.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

This privilege must be strictly confined to `Administrators` (S-1-5-32-544), `LocalService` (S-1-5-19), `NetworkService` (S-1-5-20), and `Service` (S-1-5-6). Standard users, interactive accounts, and unprivileged domain identities must never hold `SeImpersonatePrivilege`. Confining this privilege blocks potato privilege escalation from low-privileged user contexts.

### 3. MITRE ATT&CK Mapping
* **T1134.001 - Access Token Manipulation: Token Impersonation/Theft**
* **T1068 - Exploitation for Privilege Escalation**
* **T1574 - Hijack Execution Flow**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeImpersonatePrivilege` preserves normal functionality for legitimate Windows services and IIS application pools while stopping unprivileged token kidnapping. Third-party server applications running under standard user accounts that require client impersonation should be transitioned to virtual service accounts or dedicated gMSAs. Monitor Security Event ID 4672 and Event ID 4673 for sensitive impersonation calls.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Impersonate a client after authentication`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators), *S-1-5-6 (Service)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeImpersonatePrivilege.ps1](../implementation_scripts/Configure-PawUraSeImpersonatePrivilege.ps1)

```powershell
# Configure-PawUraSeImpersonatePrivilege.ps1
# Configure-PawUraSeImpersonatePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seimpersonateprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seimpersonateprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeImpersonatePrivilege\s*=") {
        $NewLines += "SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6")
    } else {
        $NewLines += "SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeImpersonatePrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeImpersonatePrivilegeStatus.ps1)

```powershell
# Get-PawUraSeImpersonatePrivilegeStatus.ps1
# Get-PawUraSeImpersonatePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seimpersonateprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeImpersonatePrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.24 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
