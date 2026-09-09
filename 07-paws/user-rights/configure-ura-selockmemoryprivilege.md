# [REQ-PAW-106] Configure User Rights: Lock pages in memory for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 and critical administrative functions. *(For Tier 2 Client Workstations and Member Servers, refer to standard baseline [REQ-END-114](../../08-endpoints/user-rights/configure-ura-selockmemoryprivilege.md)).* *(For Domain Controllers, refer to [REQ-DC-126](../../02-domain-controllers/user-rights/configure-ura-selockmemoryprivilege.md)).*
* **Operating Systems**: Windows 10 Enterprise (1809 and above) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Lock pages in memory`
  * **Privilege Constant**: `SeLockMemoryPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Lock pages in memory`
  * **Registry Location**: Stored inside local security database under privilege `SeLockMemoryPrivilege` set to `No one (Empty)`.

---

## Rationale
The `SeLockMemoryPrivilege` allows a process to lock physical memory pages in RAM using APIs such as `VirtualLock` and Address Windowing Extensions (AWE) via `AllocateUserPhysicalPages`. Locking pages prevents the Windows virtual memory manager from paging data out to disk in `pagefile.sys`, ensuring high-performance memory retention.

### 1. Technical Threat Vector & Abuse Mechanics
If granted to untrusted users or processes, `SeLockMemoryPrivilege` enables significant denial-of-service and kernel degradation attacks: (1) Memory Starvation: A malicious program can lock large swathes of physical RAM, preventing the OS memory manager from trimming working sets or servicing other processes. This leads to severe thrashing, unresponsiveness, and kernel exhaustion; (2) Security Telemetry Blind Spots: An attacker can pin memory structures containing malware artifacts, complicating memory forensics and page-table inspection.

### 2. Architectural Defense & Least Privilege Enforcement
Privileged Access Workstations (PAWs) serve as the clean-source platform for managing Tier 0 Active Directory and cloud infrastructure. Because administrative credentials exist in memory on these devices, strict isolation must be maintained at the operating system level. Restricting this user right strictly prevents lower-tier sessions, third-party software, or interactive users from interfering with administrative operations, upholding the Clean Source Principle and preventing token kidnapping or session hijacking.

Under standard security baselines, `SeLockMemoryPrivilege` must be set to `No one` (Empty). Neither interactive users nor standard system accounts should possess this right on general workstations, PAWs, or Domain Controllers. Specialized database engines (such as Microsoft SQL Server) that utilize AWE memory locking should be configured with dedicated service accounts granted this privilege explicitly only on dedicated database servers.

### 3. MITRE ATT&CK Mapping
* **T1499 - Endpoint Denial of Service**
* **T1055 - Process Injection**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Configuring `SeLockMemoryPrivilege` to `No one` has zero impact on desktop endpoints, PAWs, or Domain Controllers. Enterprise database hosts requiring Large Page allocations should receive tailored GPO exceptions on their dedicated Organizational Unit. Auditing is captured under Security Event ID 4704.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 PAW systems (e.g., `GPO_Hardening_PAW`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Lock pages in memory`**.
5. Select the **Define these policy settings** check box.
6. Click **Add User or Group...** and ensure the principal list is empty (or remove all assigned accounts/groups so that no principals are configured).
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeLockMemoryPrivilege.ps1](../implementation_scripts/Configure-PawUraSeLockMemoryPrivilege.ps1)

```powershell
# Configure-PawUraSeLockMemoryPrivilege.ps1
# Configure-PawUraSeLockMemoryPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_selockmemoryprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_selockmemoryprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeLockMemoryPrivilege\s*=") {
        $NewLines += "SeLockMemoryPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeLockMemoryPrivilege = ")
    } else {
        $NewLines += "SeLockMemoryPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeLockMemoryPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeLockMemoryPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeLockMemoryPrivilegeStatus.ps1
# Get-PawUraSeLockMemoryPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_selockmemoryprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeLockMemoryPrivilege\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.28 (L1) Ensure 'Lock pages in memory' is set to 'No One'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
