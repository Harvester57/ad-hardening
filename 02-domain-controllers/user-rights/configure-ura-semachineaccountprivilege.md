# [REQ-DC-106] Configure User Rights: Add workstations to domain on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Add workstations to domain`
  * **Privilege Constant**: `SeMachineAccountPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Add workstations to domain`
  * **Registry Location**: Stored inside local security database under privilege `SeMachineAccountPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeMachineAccountPrivilege` allows an authenticated domain user to join computer accounts to the Active Directory domain, creating new computer objects in the default `CN=Computers` container up to the limit defined by `ms-DS-MachineAccountQuota` (default: 10). This privilege is governed by the Domain Controllers policy and domain-level schema.

### 1. Technical Threat Vector & Abuse Mechanics
The ability for standard authenticated users to create computer accounts is one of the most exploited misconfigurations in Active Directory: (1) Resource-Based Constrained Delegation (RBCD): An attacker who creates a computer account controls its `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute and SPNs, enabling RBCD exploitation to compromise computer accounts across the domain; (2) Shadow Credentials (sAMAccountName Spoofing): Attackers create computer accounts to exploit vulnerabilities such as CVE-2021-42287 and CVE-2021-42278 (noPac), renaming machine accounts to match Domain Controllers and requesting elevated TGTs; (3) AD Database Pollution: Rogue computer accounts clutter the directory and provide footholds for Kerberoasting and certificate abuse.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544) on Domain Controllers. Additionally, organizations should set the domain-level attribute `ms-DS-MachineAccountQuota` to `0`. Domain joins must be performed exclusively by authorized Tier 1/2 deployment administrators using pre-staged computer objects or automated provisioning workflows.

### 3. MITRE ATT&CK Mapping
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1558 - Steal or Forge Kerberos Tickets**
* **T1134 - Access Token Manipulation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting domain join rights prevents unprivileged domain users from joining unauthorized devices or creating rogue computer objects. IT deployment teams must utilize pre-staged computer accounts in dedicated OUs or deploy workstations using automated imaging systems (e.g., MECM, Autopilot, MDT) configured with service accounts delegated specific OU join permissions. Computer account creation generates Directory Service Event ID 4741.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Add workstations to domain`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeMachineAccountPrivilege.ps1](../implementation_scripts/Configure-DcUraSeMachineAccountPrivilege.ps1)

```powershell
# Configure-DcUraSeMachineAccountPrivilege.ps1
# Configure-DcUraSeMachineAccountPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_semachineaccountprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_semachineaccountprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeMachineAccountPrivilege\s*=") {
        $NewLines += "SeMachineAccountPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeMachineAccountPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeMachineAccountPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeMachineAccountPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeMachineAccountPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeMachineAccountPrivilegeStatus.ps1
# Get-DcUraSeMachineAccountPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_semachineaccountprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeMachineAccountPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.1 (L1) Ensure 'Add workstations to domain' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
