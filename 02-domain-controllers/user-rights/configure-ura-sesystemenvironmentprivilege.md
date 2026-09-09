# [REQ-DC-130] Configure User Rights: Modify firmware environment values on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure). *(For Tier 0 Privileged Access Workstations, refer to tightened baseline [REQ-PAW-108](../../07-paws/user-rights/configure-ura-sesystemenvironmentprivilege.md)).* *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-116](../../08-endpoints/user-rights/configure-ura-sesystemenvironmentprivilege.md)).*
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Modify firmware environment values`
  * **Privilege Constant**: `SeSystemEnvironmentPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Modify firmware environment values`
  * **Registry Location**: Stored inside local security database under privilege `SeSystemEnvironmentPrivilege` set to `*S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeSystemEnvironmentPrivilege` allows a process to query and modify Non-Volatile RAM (NVRAM) firmware environment variables via Win32 APIs `GetFirmwareEnvironmentVariable` and `SetFirmwareEnvironmentVariable`. NVRAM variables govern UEFI boot sequences, Secure Boot policies, boot configuration data (BCD) handoffs, and hardware configuration flags.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries exploit `SeSystemEnvironmentPrivilege` to install firmware bootkits and undermine OS integrity: (1) Secure Boot Bypasses: Attackers alter UEFI NVRAM variables to invalidate Secure Boot validation, allowing unsigned bootloaders or malicious early-launch payloads (e.g., BlackLotus UEFI bootkit) to execute before the Windows kernel loads; (2) Hypervisor Tampering: Modifying virtualization parameters in NVRAM can weaken Virtualization-Based Security (VBS) and Credential Guard; (3) Persistence: Firmware modifications persist across complete OS re-installations and drive replacements.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted strictly to `Administrators` (S-1-5-32-544). Standard users, interactive accounts, and standard applications must never be permitted to modify firmware environment variables.

### 3. MITRE ATT&CK Mapping
* **T1542.001 - Pre-OS Boot: System Firmware**
* **T1562.001 - Impair Defenses: Disable or Modify Tools**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeSystemEnvironmentPrivilege` to `Administrators` protects UEFI firmware integrity. Firmware update tools (e.g., OEM BIOS flashers) running under administrative credentials operate normally. Auditing is captured under Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Modify firmware environment values`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeSystemEnvironmentPrivilege.ps1](../implementation_scripts/Configure-DcUraSeSystemEnvironmentPrivilege.ps1)

```powershell
# Configure-DcUraSeSystemEnvironmentPrivilege.ps1
# Configure-DcUraSeSystemEnvironmentPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sesystemenvironmentprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sesystemenvironmentprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeSystemEnvironmentPrivilege\s*=") {
        $NewLines += "SeSystemEnvironmentPrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeSystemEnvironmentPrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeSystemEnvironmentPrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeSystemEnvironmentPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeSystemEnvironmentPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeSystemEnvironmentPrivilegeStatus.ps1
# Get-DcUraSeSystemEnvironmentPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sesystemenvironmentprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeSystemEnvironmentPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.39 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
