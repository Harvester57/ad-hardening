# [REQ-DC-122] Configure User Rights: Enable computer and user accounts to be trusted for delegation on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-102](../../07-paws/user-rights/configure-ura-seenabledelegationprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-109](../../08-endpoints/user-rights/configure-ura-seenabledelegationprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Enable computer and user accounts to be trusted for delegation`
  * **Privilege Constant**: `SeEnableDelegationPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Enable computer and user accounts to be trusted for delegation`
  * **Registry Location**: Stored inside local security database under privilege `SeEnableDelegationPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeEnableDelegationPrivilege` allows a security principal to modify the `userAccountControl` attribute on Active Directory user and computer objects to enable Kerberos Delegation flags: (1) `TRUSTED_FOR_DELEGATION` (Unconstrained Delegation); (2) `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` (Constrained Delegation with Protocol Transition / S4U2Self). Kerberos delegation permits a service to impersonate an authenticated user to access back-end resources on their behalf.

### 1. Technical Threat Vector & Abuse Mechanics
Misused or abused delegation is one of the most devastating privilege escalation and persistence vectors in Active Directory: (1) Unconstrained Delegation: When a user authenticates to a server with unconstrained delegation, the Domain Controller embeds a copy of the user's Ticket Granting Ticket (TGT) in the service ticket. An attacker who controls a machine or service with unconstrained delegation can harvest TGTs of visiting Domain Admins from memory and achieve immediate, full domain compromise; (2) Protocol Transition Abuse: An attacker with rights to configure constrained delegation can configure an account to impersonate any domain user to target services without requiring the user's password; (3) Computer Account Hijacking: Granting this privilege allows an attacker to create rogue delegation pathways across the forest.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

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
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Enable computer and user accounts to be trusted for delegation`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeEnableDelegationPrivilege.ps1](../implementation_scripts/Configure-DcUraSeEnableDelegationPrivilege.ps1)

```powershell
# Configure-DcUraSeEnableDelegationPrivilege.ps1
# Configure-DcUraSeEnableDelegationPrivilege.ps1
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
        $NewLines += "SeEnableDelegationPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeEnableDelegationPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeEnableDelegationPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeEnableDelegationPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeEnableDelegationPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeEnableDelegationPrivilegeStatus.ps1
# Get-DcUraSeEnableDelegationPrivilegeStatus.ps1
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
* **CIS Benchmark**: 2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (Workstations/PAWs) / 'Administrators' (DCs)
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
