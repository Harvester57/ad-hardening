# [REQ-DC-107] Configure User Rights: Adjust memory quotas for a process on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Adjust memory quotas for a process`
  * **Privilege Constant**: `SeIncreaseQuotaPrivilege`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Adjust memory quotas for a process`
  * **Registry Location**: Stored inside local security database under privilege `SeIncreaseQuotaPrivilege` set to `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators)`.

---

## Rationale
The `SeIncreaseQuotaPrivilege` grants a process the capability to increase the maximum memory quota (working set size and page pool limits) allocated to a process via `SetProcessWorkingSetSize` or `NtSetInformationProcess`. The memory manager enforces memory quotas to prevent individual processes from monopolizing system memory pools.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries can exploit `SeIncreaseQuotaPrivilege` to manipulate process resource allocation or participate in token/process spawning operations. In certain legacy token manipulation scenarios, `SeIncreaseQuotaPrivilege` is required alongside `SeAssignPrimaryTokenPrivilege` to initialize process memory quotas when launching processes under alternative user contexts. Unrestricted modification of memory quotas can also be abused to exhaust non-paged pool memory, precipitating system crashes.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

This privilege must be restricted strictly to `Administrators` (S-1-5-32-544), `LocalService` (S-1-5-19), and `NetworkService` (S-1-5-20). Standard users, unprivileged domain accounts, and non-system services must be excluded.

### 3. MITRE ATT&CK Mapping
* **T1499 - Endpoint Denial of Service**
* **T1068 - Exploitation for Privilege Escalation**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeIncreaseQuotaPrivilege` prevents unauthorized memory quota adjustments. Standard business applications and operating system services function normally under standard quota parameters. Administrative invocations are tracked via Security Event ID 4672.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Adjust memory quotas for a process`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-19 (LocalService), *S-1-5-20 (NetworkService), *S-1-5-32-544 (Administrators)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeIncreaseQuotaPrivilege.ps1](../implementation_scripts/Configure-DcUraSeIncreaseQuotaPrivilege.ps1)

```powershell
# Configure-DcUraSeIncreaseQuotaPrivilege.ps1
# Configure-DcUraSeIncreaseQuotaPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_seincreasequotaprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_seincreasequotaprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeIncreaseQuotaPrivilege\s*=") {
        $NewLines += "SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544")
    } else {
        $NewLines += "SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeIncreaseQuotaPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeIncreaseQuotaPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeIncreaseQuotaPrivilegeStatus.ps1
# Get-DcUraSeIncreaseQuotaPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_seincreasequotaprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeIncreaseQuotaPrivilege\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-19,*S-1-5-20,*S-1-5-32-544"
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
* **CIS Benchmark**: 2.2.2 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
