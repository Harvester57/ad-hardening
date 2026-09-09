# [REQ-DC-117] Configure User Rights: Deny access to this computer from the network on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-113](../../07-paws/user-rights/configure-ura-sedenynetworklogonright.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-124](../../08-endpoints/user-rights/configure-ura-sedenynetworklogonright.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Deny access to this computer from the network`
  * **Privilege Constant**: `SeDenyNetworkLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny access to this computer from the network`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyNetworkLogonRight` set to `*S-1-5-32-546 (Guests)`.

---

## Rationale
The `SeDenyNetworkLogonRight` explicitly prevents specified security principals from authenticating over network protocols (SMB, RPC, WMI, WinRM, LDAP, etc. - Logon Type 3). Network logons represent the primary highway for lateral movement and remote compromise in Active Directory environments. Enforcing an explicit deny stops network authentication regardless of share-level or NTFS-level permissions.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries extensively leverage Pass-the-Hash (PtH) and credential reuse attacks across workstations and member servers using local account credentials (e.g., the built-in Administrator account). If local accounts are permitted to authenticate over the network, an attacker who extracts the local administrator hash from one workstation can authenticate over SMB/RPC to every other workstation in the fleet that shares the same password. On PAWs and Endpoints, denying network logon to `Local Account` (S-1-5-113) and `Local account and member of Administrators group` (S-1-5-114) completely destroys this lateral movement vector, confining local account credentials strictly to the physical machine.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Endpoints and PAWs, configure `SeDenyNetworkLogonRight` to include `Local Account` (S-1-5-113), `Local account and member of Administrators group` (S-1-5-114), and `Guests` (S-1-5-32-546). On Domain Controllers, configure to include `Guests` (S-1-5-32-546). This configuration neutralizes lateral movement using local credentials while preserving domain-based administrative management.

### 3. MITRE ATT&CK Mapping
* **T1021.002 - Remote Services: SMB/Windows Admin Shares**
* **T1021.006 - Remote Services: Windows Remote Management**
* **T1550.002 - Use Alternate Authentication Material: Pass the Hash**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Denying network logon to local accounts prevents remote administrative tools (such as remote PsExec or remote script blocks) from authenticating using local credentials. Remote administration must be performed using domain-joined administrative accounts or centralized management solutions (e.g., LAPS, Microsoft Intune, SCCM). Blocked network connection attempts are logged under Security Event ID 4625.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Deny access to this computer from the network`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-546 (Guests)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeDenyNetworkLogonRight.ps1](../implementation_scripts/Configure-DcUraSeDenyNetworkLogonRight.ps1)

```powershell
# Configure-DcUraSeDenyNetworkLogonRight.ps1
# Configure-DcUraSeDenyNetworkLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenynetworklogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenynetworklogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyNetworkLogonRight\s*=") {
        $NewLines += "SeDenyNetworkLogonRight = *S-1-5-32-546"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyNetworkLogonRight = *S-1-5-32-546")
    } else {
        $NewLines += "SeDenyNetworkLogonRight = *S-1-5-32-546"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeDenyNetworkLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeDenyNetworkLogonRightStatus.ps1)

```powershell
# Get-DcUraSeDenyNetworkLogonRightStatus.ps1
# Get-DcUraSeDenyNetworkLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenynetworklogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyNetworkLogonRight\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-32-546"
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
* **CIS Benchmark**: 2.2.18 (L1) Ensure 'Deny access to this computer from the network' includes 'Guests, Local account and member of Administrators group'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
