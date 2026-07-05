# [REQ-PAW-114] Configure User Rights: Deny log on through Remote Desktop Services for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on through Remote Desktop Services`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyRemoteInteractiveLogonRight` set to `*S-1-5-113,*S-1-5-114`.

---

## Rationale
Explicitly blocks Remote Desktop logons for Local Accounts (S-1-5-113) and Local Administrators (S-1-5-114), forcing administrators to connect using domain credentials over secure paths.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeDenyRemoteInteractiveLogonRight` to `*S-1-5-113,*S-1-5-114` enforces maximum console and credential isolation. No productivity tools or standard non-administrative domain sessions should exist on PAW consoles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Deny log on through Remote Desktop Services`.
3. Configure the security principal allocation to: `*S-1-5-113,*S-1-5-114`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1](../implementation_scripts/Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1)

```powershell
# Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1
# Configure-PawUraSeDenyRemoteInteractiveLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenyremoteinteractivelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenyremoteinteractivelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyRemoteInteractiveLogonRight\s*=") {
        $NewLines += "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114")
    } else {
        $NewLines += "SeDenyRemoteInteractiveLogonRight = *S-1-5-113,*S-1-5-114"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1](../audit_scripts/Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1)

```powershell
# Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1
# Get-PawUraSeDenyRemoteInteractiveLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenyremoteinteractivelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyRemoteInteractiveLogonRight\s*=\s*(.*)$"
$CurrentValue = ""
if ($Match) {
    $CurrentValue = $Matches[1].Trim()
}

$Expected = "*S-1-5-113,*S-1-5-114"
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
