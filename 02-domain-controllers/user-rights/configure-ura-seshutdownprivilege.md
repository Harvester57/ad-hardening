# [REQ-DC-133] Configure User Rights: Shut down the system on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Shut down the system`
  * **Privilege Constant**: `SeShutdownPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Shut down the system`
  * **Registry Location**: Stored inside local security database under privilege `SeShutdownPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeShutdownPrivilege` controls the capability of a user logged on locally at the console to cleanly shut down or restart the local operating system via the `ExitWindowsEx` or `InitiateSystemShutdown` APIs.

### 1. Technical Threat Vector & Abuse Mechanics
On mission-critical servers and Domain Controllers, allowing unauthorized users to trigger system shutdowns creates severe denial-of-service risks: (1) Service Interruption: Shutting down a Domain Controller halts Kerberos authentication, directory lookups, and LDAP services for all dependent clients; (2) Replication Disruption: Unexpected shutdowns can cause directory database (`ntds.dit`) corruption or replication delays across domain controllers; (3) Coerced Reboots: Attackers can trigger reboots to activate pending kernel payloads or force administrators to enter recovery keys.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

On Domain Controllers, `SeShutdownPrivilege` must be restricted strictly to `Administrators` (S-1-5-32-544). Standard domain users, operator accounts, and guest accounts must never be permitted to shut down Domain Controllers.

### 3. MITRE ATT&CK Mapping
* **T1529 - System Shutdown/Reboot**
* **T1499 - Endpoint Denial of Service**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeShutdownPrivilege` to `Administrators` prevents accidental or malicious local shutdowns of Domain Controllers. Standard administrative maintenance procedures remain fully supported for Domain Administrators. Shutdown events are logged under System Event ID 1074.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Shut down the system`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeShutdownPrivilege.ps1](../implementation_scripts/Configure-DcUraSeShutdownPrivilege.ps1)

```powershell
# Configure-DcUraSeShutdownPrivilege.ps1
# Configure-DcUraSeShutdownPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seshutdownprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seshutdownprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeShutdownPrivilege\s*=") {
        $NewLines += "SeShutdownPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeShutdownPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeShutdownPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeShutdownPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeShutdownPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeShutdownPrivilegeStatus.ps1
# Get-DcUraSeShutdownPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seshutdownprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeShutdownPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.36 (L1) Ensure 'Shut down the system' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
