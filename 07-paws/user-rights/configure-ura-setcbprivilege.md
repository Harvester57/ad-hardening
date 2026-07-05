# [REQ-PAW-094] Configure User Rights: Act as part of the operating system for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Act as part of the operating system`
  * **Registry Location**: Stored inside local security database under privilege `SeTcbPrivilege` set to `No one (Empty)`.

---

## Rationale
Allows a process to impersonate any user without credentials. This privilege is equivalent to local SYSTEM and should be completely empty to prevent privilege escalation.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeTcbPrivilege` to `No one (Empty)` enforces maximum console and credential isolation. No productivity tools or standard non-administrative domain sessions should exist on PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Act as part of the operating system`.
3. Configure the security principal allocation to: `No one (Empty)`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeTcbPrivilege.ps1](../implementation_scripts/Configure-PawUraSeTcbPrivilege.ps1)

```powershell
# Configure-PawUraSeTcbPrivilege.ps1
# Configure-PawUraSeTcbPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setcbprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setcbprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTcbPrivilege\s*=") {
        $NewLines += "SeTcbPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTcbPrivilege = ")
    } else {
        $NewLines += "SeTcbPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeTcbPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeTcbPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeTcbPrivilegeStatus.ps1
# Get-PawUraSeTcbPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setcbprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTcbPrivilege\s*=\s*(.*)$"
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
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Privileged Access Workstations
* **Microsoft Security Baseline**: User Rights Configuration specifications
