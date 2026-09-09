# [REQ-DC-118] Configure User Rights: Deny log on as a batch job on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Deny log on as a batch job`
  * **Privilege Constant**: `SeDenyBatchLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a batch job`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyBatchLogonRight` set to `*S-1-5-32-546 (Guests)`.

---

## Rationale
The `SeDenyBatchLogonRight` explicitly denies designated security principals the ability to authenticate and run batch or scheduled workloads (Logon Type 4). In Windows security, an explicit 'Deny' right takes precedence over any conflicting 'Allow' right (`SeBatchLogonRight`), ensuring that restricted accounts cannot be granted batch execution through nested group memberships.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries who compromise unprivileged, guest, or local utility accounts often attempt to establish persistence by scheduling batch jobs or background tasks. Explicitly denying batch logon to untrusted principals (such as the local `Guests` group) ensures that guest accounts and low-privilege accounts cannot be leveraged to maintain unattended script execution or abuse task automation to evade interactive logon detection.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

Baseline standards require that `SeDenyBatchLogonRight` be configured to include `Guests` (S-1-5-32-546). This configuration guarantees that guest accounts cannot execute scheduled tasks or unattended scripts under any circumstances.

### 3. MITRE ATT&CK Mapping
* **T1053.005 - Scheduled Task/Job: Scheduled Task**
* **T1078.001 - Valid Accounts: Default Accounts**
* **T1078.003 - Valid Accounts: Local Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Denying batch logon to `Guests` does not impact standard enterprise administrative tasks or production batch jobs executed by legitimate administrators. Any attempt by restricted accounts to execute a batch job fails with logon failure error `STATUS_LOGON_TYPE_NOT_GRANTED` and generates Security Event ID 4625.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Deny log on as a batch job`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-546 (Guests)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeDenyBatchLogonRight.ps1](../implementation_scripts/Configure-DcUraSeDenyBatchLogonRight.ps1)

```powershell
# Configure-DcUraSeDenyBatchLogonRight.ps1
# Configure-DcUraSeDenyBatchLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenybatchlogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenybatchlogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyBatchLogonRight\s*=") {
        $NewLines += "SeDenyBatchLogonRight = *S-1-5-32-546"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyBatchLogonRight = *S-1-5-32-546")
    } else {
        $NewLines += "SeDenyBatchLogonRight = *S-1-5-32-546"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeDenyBatchLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeDenyBatchLogonRightStatus.ps1)

```powershell
# Get-DcUraSeDenyBatchLogonRightStatus.ps1
# Get-DcUraSeDenyBatchLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenybatchlogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyBatchLogonRight\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.16 (L1) Ensure 'Deny log on as a batch job' includes 'Guests'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
