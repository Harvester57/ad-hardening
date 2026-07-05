# [REQ-PAW-092] Configure User Rights: Access Credential Manager as a trusted caller for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Access Credential Manager as a trusted caller`
  * **Registry Location**: Stored inside local security database under privilege `SeTrustedCredManAccessPrivilege` set to `No one (Empty)`.

---

## Rationale
No security principals should hold this privilege on PAWs. It prevents attackers from using compromised components to access stored credentials in the Credential Manager.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeTrustedCredManAccessPrivilege` to `No one (Empty)` enforces maximum console and credential isolation. No productivity tools or standard non-administrative domain sessions should exist on PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Access Credential Manager as a trusted caller`.
3. Configure the security principal allocation to: `No one (Empty)`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeTrustedCredManAccessPrivilege.ps1](../implementation_scripts/Configure-PawUraSeTrustedCredManAccessPrivilege.ps1)

```powershell
# Configure-PawUraSeTrustedCredManAccessPrivilege.ps1
# Configure-PawUraSeTrustedCredManAccessPrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_setrustedcredmanaccessprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_setrustedcredmanaccessprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeTrustedCredManAccessPrivilege\s*=") {
        $NewLines += "SeTrustedCredManAccessPrivilege = "
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeTrustedCredManAccessPrivilege = ")
    } else {
        $NewLines += "SeTrustedCredManAccessPrivilege = "
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeTrustedCredManAccessPrivilegeStatus.ps1](../audit_scripts/Get-PawUraSeTrustedCredManAccessPrivilegeStatus.ps1)

```powershell
# Get-PawUraSeTrustedCredManAccessPrivilegeStatus.ps1
# Get-PawUraSeTrustedCredManAccessPrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_setrustedcredmanaccessprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeTrustedCredManAccessPrivilege\s*=\s*(.*)$"
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
