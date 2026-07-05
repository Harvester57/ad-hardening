# [REQ-DC-126] Configure User Rights: Lock pages in memory on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Lock pages in memory`
  * **Registry Location**: Stored inside local security database under privilege `SeLockMemoryPrivilege` set to `No one (Empty)`.

---

## Rationale
Must be empty on DCs to prevent locking memory segments and resource exhaustion.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeLockMemoryPrivilege` to `No one (Empty)` protects Domain Controllers filesystem and service execution interfaces. Ensure core directory sync or backup agents do not lose validation access.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Lock pages in memory`.
3. Configure the security principal allocation to: `No one (Empty)`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeLockMemoryPrivilege.ps1](../implementation_scripts/Configure-DcUraSeLockMemoryPrivilege.ps1)

```powershell
# Configure-DcUraSeLockMemoryPrivilege.ps1
# Configure-DcUraSeLockMemoryPrivilege.ps1
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
[Download Script: Get-DcUraSeLockMemoryPrivilegeStatus.ps1](../audit_scripts/Get-DcUraSeLockMemoryPrivilegeStatus.ps1)

```powershell
# Get-DcUraSeLockMemoryPrivilegeStatus.ps1
# Get-DcUraSeLockMemoryPrivilegeStatus.ps1
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

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
* **Microsoft Security Baseline**: User Rights Configuration specifications
