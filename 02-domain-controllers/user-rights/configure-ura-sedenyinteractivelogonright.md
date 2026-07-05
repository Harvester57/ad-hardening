# [REQ-DC-120] Configure User Rights: Deny log on locally on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers.
* **Operating Systems**: Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on locally`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyInteractiveLogonRight` set to `*S-1-5-32-546`.

---

## Rationale
Denies Guests local interactive logons to Domain Controllers.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeDenyInteractiveLogonRight` to `*S-1-5-32-546` protects Domain Controllers filesystem and service execution interfaces. Ensure core directory sync or backup agents do not lose validation access.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Deny log on locally`.
3. Configure the security principal allocation to: `*S-1-5-32-546`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeDenyInteractiveLogonRight.ps1](../implementation_scripts/Configure-DcUraSeDenyInteractiveLogonRight.ps1)

```powershell
# Configure-DcUraSeDenyInteractiveLogonRight.ps1
# Configure-DcUraSeDenyInteractiveLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenyinteractivelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenyinteractivelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyInteractiveLogonRight\s*=") {
        $NewLines += "SeDenyInteractiveLogonRight = *S-1-5-32-546"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyInteractiveLogonRight = *S-1-5-32-546")
    } else {
        $NewLines += "SeDenyInteractiveLogonRight = *S-1-5-32-546"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeDenyInteractiveLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeDenyInteractiveLogonRightStatus.ps1)

```powershell
# Get-DcUraSeDenyInteractiveLogonRightStatus.ps1
# Get-DcUraSeDenyInteractiveLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenyinteractivelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyInteractiveLogonRight\s*=\s*(.*)$"
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

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: Protective controls baselines on Domain Controllers
* **Microsoft Security Baseline**: User Rights Configuration specifications
