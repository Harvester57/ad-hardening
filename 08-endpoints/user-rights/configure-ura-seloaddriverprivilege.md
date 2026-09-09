# [REQ-END-113] Configure User Rights: Load and unload device drivers

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers. *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-105](../../07-paws/user-rights/configure-ura-seloaddriverprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-125](../../02-domain-controllers/user-rights/configure-ura-seloaddriverprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Pro, Windows Server 2016, 2019, 2022, and 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Load and unload device drivers`
  * **Privilege Constant**: `SeLoadDriverPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Load and unload device drivers`
  * **Registry Location**: Stored inside local security database under privilege `SeLoadDriverPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeLoadDriverPrivilege` allows a process to dynamically load and unload kernel-mode device drivers (`.sys` files) via `NtLoadDriver` or the Service Control Manager (`CreateService` with `SERVICE_KERNEL_DRIVER`). Kernel-mode drivers execute in Ring 0 with unrestricted hardware access, full kernel memory read/write permissions, and the ability to execute any CPU instruction.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries extensively abuse `SeLoadDriverPrivilege` in Bring Your Own Vulnerable Driver (BYOVD) attacks. Modern Windows enforces Driver Signature Enforcement (DSE), preventing the loading of unsigned code into kernel space. However, an attacker with `SeLoadDriverPrivilege` can drop an authentic, cryptographically signed, legitimate driver that contains known security vulnerabilities (e.g., `gdrv.sys`, `mhyprot2.sys`, `RTCore64.sys`, or `procexp.sys`). Once loaded, the attacker exploits the driver's kernel read/write IOCTLs to: (1) Bludgeon and terminate Endpoint Detection and Response (EDR) processes; (2) Direct Kernel Object Manipulation (DKOM) to hide processes and alter process tokens; (3) Disable ETW-TI (Threat Intelligence) telemetry hooks.

### 2. Architectural Defense & Least Privilege Enforcement
On general workstations and member servers, enforcing least privilege for this user right is critical for host isolation. Preventing unprivileged users or rogue applications from exercising this right stops local privilege escalation (LPE) and blocks adversaries from leveraging co-located user sessions to harvest credentials or pivot across the corporate subnet.

This privilege must be restricted exclusively to `Administrators` (S-1-5-32-544). No standard users, service accounts, or automated operators must be granted driver loading rights. Driver loading should be further constrained using Windows Defender Application Control (WDAC) and the Microsoft Recommended Driver Blocklist.

### 3. MITRE ATT&CK Mapping
* **T1068 - Exploitation for Privilege Escalation**
* **T1543.003 - Create or Modify System Process: Windows Service**
* **T1562.001 - Impair Defenses: Disable or Modify Tools**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeLoadDriverPrivilege` to `Administrators` ensures only authorized administrative processes can install kernel drivers. Standard hardware plug-and-play driver installations for pre-approved devices function normally through the Windows Driver Store without requiring user-level driver loading privileges. Driver load operations are logged under System Event ID 7045 and Security Event ID 4672/4673.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 2 systems (e.g., `GPO_Hardening_Endpoints`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Load and unload device drivers`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeLoadDriverPrivilege.ps1](../implementation_scripts/Configure-UraSeLoadDriverPrivilege.ps1)

```powershell
# Configure-UraSeLoadDriverPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seloaddriverprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seloaddriverprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeLoadDriverPrivilege\s*=") {
        $NewLines += "SeLoadDriverPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeLoadDriverPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeLoadDriverPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeLoadDriverPrivilegeStatus.ps1](../audit_scripts/Get-UraSeLoadDriverPrivilegeStatus.ps1)

```powershell
# Get-UraSeLoadDriverPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seloaddriverprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeLoadDriverPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.27 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
