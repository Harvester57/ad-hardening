# [REQ-DC-128] Configure User Rights: Log on as a service on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Log on as a service`
  * **Privilege Constant**: `SeServiceLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Log on as a service`
  * **Registry Location**: Stored inside local security database under privilege `SeServiceLogonRight` set to `No one (Empty)`.

---

## Rationale
The `SeServiceLogonRight` determines which security principals are permitted to register and authenticate as background Windows service accounts (Logon Type 5). When the Service Control Manager (`services.exe`) starts a service configured with a user account, it initiates a service logon session.

### 1. Technical Threat Vector & Abuse Mechanics
Uncontrolled service logon rights present severe persistence and credential exposure vulnerabilities: (1) Rogue Service Persistence: An adversary who compromises user credentials possessing this right can configure rogue Windows services that execute unattended malicious binaries across reboots; (2) Credential Caching: Standard user accounts running services expose their password hashes and Kerberos tickets to LSASS memory; (3) On Domain Controllers: Running services under broad user accounts or standard service accounts provides avenues for Kerberoasting and ticket extraction.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Domain Controllers, `SeServiceLogonRight` should be strictly set to `No one` (Empty) in baseline GPOs, or restricted strictly to dedicated Group Managed Service Accounts (gMSAs). Standard domain users and unmanaged service accounts must never be granted service logon rights on Domain Controllers. Migrating services to gMSAs eliminates static passwords and automates credential management.

### 3. MITRE ATT&CK Mapping
* **T1543.003 - Create or Modify System Process: Windows Service**
* **T1078.002 - Valid Accounts: Domain Accounts**
* **T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Enforcing empty or gMSA-only service logon rights on Domain Controllers ensures that rogue services cannot be registered under standard user identities. Third-party monitoring or antivirus agents deployed on Domain Controllers must be evaluated and migrated to run under `LocalSystem`, `LocalService`, `NetworkService`, or gMSAs. Service logons generate Security Event ID 4624 (Logon Type 5).

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Log on as a service`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeServiceLogonRight.ps1](../implementation_scripts/Configure-DcUraSeServiceLogonRight.ps1)

```powershell
# Configure-DcUraSeServiceLogonRight.ps1
# Configure-DcUraSeServiceLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seservicelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seservicelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeServiceLogonRight\s*=") {
        $NewLines += "SeServiceLogonRight = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeServiceLogonRight = ")
    } else {
        $NewLines += "SeServiceLogonRight = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeServiceLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeServiceLogonRightStatus.ps1)

```powershell
# Get-DcUraSeServiceLogonRightStatus.ps1
# Get-DcUraSeServiceLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seservicelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeServiceLogonRight\s*=\s*(.*)$"
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
* **ANSSI Active Directory Hardening Guide**: ANSSI Active Directory Hardening Guide: R29 (Logon Rights Assignment)
* **CIS Benchmark**: 2.2.32 (L1) Ensure 'Log on as a service' is set to 'No One' (or dedicated gMSAs on DCs)
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
