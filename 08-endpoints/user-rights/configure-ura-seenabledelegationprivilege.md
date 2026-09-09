# [REQ-END-109] Configure User Rights: Enable computer and user accounts to be trusted for delegation

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-102](../../07-paws/user-rights/configure-ura-seenabledelegationprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-122](../../02-domain-controllers/user-rights/configure-ura-seenabledelegationprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Enable computer and user accounts to be trusted for delegation`
  * **Privilege Constant**: `SeEnableDelegationPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Enable computer and user accounts to be trusted for delegation`
  * **Registry Location**: Stored inside local security database under privilege `SeEnableDelegationPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeEnableDelegationPrivilege` allows a security principal to modify the `userAccountControl` attribute on Active Directory user and computer objects to enable Kerberos Delegation flags: (1) `TRUSTED_FOR_DELEGATION` (Unconstrained Delegation); (2) `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (Constrained Delegation with Protocol Transition / S4U2Self). Kerberos delegation permits a service to impersonate an authenticated user to access back-end resources on their behalf.

### 1. Technical Threat Vector & Abuse Mechanics
Misused or abused delegation is one of the most devastating privilege escalation and persistence vectors in Active Directory: (1) Unconstrained Delegation: When a user authenticates to a server with unconstrained delegation, the Domain Controller embeds a copy of the user's Ticket Granting Ticket (TGT) in the service ticket. An attacker who controls a machine or service with unconstrained delegation can harvest TGTs of visiting Domain Admins from memory and achieve immediate, full domain compromise; (2) Protocol Transition Abuse: An attacker with rights to configure constrained delegation can configure an account to impersonate any domain user to target services without requiring the user's password; (3) Computer Account Hijacking: Granting this privilege allows an attacker to create rogue delegation pathways across the forest.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

On Endpoints and PAWs, `SeEnableDelegationPrivilege` must be strictly set to `No one` (Empty). Workstations and member servers must never have the authority to configure Kerberos delegation. On Domain Controllers, this right must be strictly restricted to `Administrators` (S-1-5-32-544), and delegation changes must be subject to strict change management.

### 3. MITRE ATT&CK Mapping
* **T1558 - Steal or Forge Kerberos Tickets**
* **T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting**
* **T1134.005 - Access Token Manipulation: SID History Injection**
* **T1078.002 - Valid Accounts: Domain Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeEnableDelegationPrivilege` prevents unauthorized configuration of Kerberos delegation. Standard administrative workflows are unaffected, as delegation configuration is performed centrally on Domain Controllers by Domain Administrators. Audit Security Event ID 4738 (A user account was modified) and Event ID 4742 (A computer account was modified) for delegation flag updates.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Enable computer and user accounts to be trusted for delegation`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeEnableDelegationPrivilege.ps1](../implementation_scripts/Configure-UraSeEnableDelegationPrivilege.ps1)

```powershell
# Configure-UraSeEnableDelegationPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seenabledelegationprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seenabledelegationprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeEnableDelegationPrivilege\s*=") {
        $NewLines += "SeEnableDelegationPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeEnableDelegationPrivilege = ")
    } else {
        $NewLines += "SeEnableDelegationPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeEnableDelegationPrivilegeStatus.ps1](../audit_scripts/Get-UraSeEnableDelegationPrivilegeStatus.ps1)

```powershell
# Get-UraSeEnableDelegationPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seenabledelegationprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeEnableDelegationPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (Workstations/PAWs) / 'Administrators' (DCs)
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
