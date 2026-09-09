# [REQ-DC-134] Configure User Rights: Synchronize directory service data on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Synchronize directory service data`
  * **Privilege Constant**: `SeSyncAgentPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Synchronize directory service data`
  * **Registry Location**: Stored inside local security database under privilege `SeSyncAgentPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeSyncAgentPrivilege` grants the caller the authority to initiate directory synchronization operations against Active Directory domain partitions. This privilege is the underlying Windows user right associated with the directory service replication extended rights: `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, and `DS-Replication-Get-Changes-In-Filtered-Set`.

### 1. Technical Threat Vector & Abuse Mechanics
This user right is the foundation of the catastrophic DCSync attack: (1) DCSync Attack Execution: An adversary who compromises an account possessing `SeSyncAgentPrivilege` can use Mimikatz (`lsadump::dcsync`) to masquerade as a Domain Controller. Using the Directory Replication Service Remote Protocol (MS-DRSR), the attacker requests password hashes directly from a Domain Controller without executing any code on the DC itself; (2) Full Domain Compromise: The attacker extracts the password hash of `KRBTGT` (enabling Golden Ticket creation) and all Domain Administrator accounts; (3) Persistence: Rogue replication grants provide enduring stealthy persistence across forest domains.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be strictly configured to `No one` (Empty) in Group Policy. Legitimate Domain Controllers participate in replication via their computer account memberships in `Enterprise Domain Controllers` and `Domain Controllers` groups through explicit directory schema permissions. No human user account or third-party service account should ever be granted `SeSyncAgentPrivilege`.

### 3. MITRE ATT&CK Mapping
* **T1003.006 - OS Credential Dumping: DCSync**
* **T1558 - Steal or Forge Kerberos Tickets**
* **T1078.002 - Valid Accounts: Domain Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Setting `SeSyncAgentPrivilege` to `No one` in GPO prevents unauthorized replication grants while preserving legitimate Domain Controller-to-Domain Controller replication. Azure AD Connect (Entra Connect) synchronization accounts require specific replication permissions; these must be delegated specifically at the domain root object rather than granting broad user rights. DCSync attempts generate Directory Service Event ID 4662.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Synchronize directory service data`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeSyncAgentPrivilege.ps1](../implementation_scripts/Configure-DcUraSeSyncAgentPrivilege.ps1)

```powershell
# Configure-DcUraSeSyncAgentPrivilege.ps1
# Configure-DcUraSeSyncAgentPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sesyncagentprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sesyncagentprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeSyncAgentPrivilege\s*=") {
        $NewLines += "SeSyncAgentPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeSyncAgentPrivilege = ")
    } else {
        $NewLines += "SeSyncAgentPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeSyncAgentPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeSyncAgentPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeSyncAgentPrivilegeStatus.ps1
# Get-DcUraSeSyncAgentPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sesyncagentprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeSyncAgentPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.38 (L1) Ensure 'Synchronize directory service data' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
