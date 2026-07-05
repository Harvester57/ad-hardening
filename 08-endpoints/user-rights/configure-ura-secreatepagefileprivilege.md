# [REQ-END-103] Configure User Rights: Create a pagefile

## Target Scope
* **Applicable Systems**: Member Servers, Tier 2 Clients (Windows 10/11)
* **Operating Systems**: Windows Server 2016 (and above), Windows 10/11 Enterprise/Professional

---

## Implementation Details
* **Priority**: Low
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Create a pagefile`
  * **Registry Location**: Stored inside local security database under privilege `SeCreatePagefilePrivilege` set to `*S-1-5-32-544`.

---

## Rationale
Allows users to create and change the size of page files. Restricting this to Administrators prevents standard users from exhausting disk space or dumping system paging data.

---

## Legacy Impact & Compatibility
* **Operational Impact**: Restricting `SeCreatePagefilePrivilege` to `*S-1-5-32-544` prevents unauthorized local or network actions. Verify if custom service accounts require this privilege before deploying.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Navigate to: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
2. Open the policy `Create a pagefile`.
3. Configure the security principal allocation to: `*S-1-5-32-544`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-UraSeCreatePagefilePrivilege.ps1](../implementation_scripts/Configure-UraSeCreatePagefilePrivilege.ps1)

```powershell
# Configure-UraSeCreatePagefilePrivilege.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_secreatepagefileprivilege.cfg"
$DbFile = Join-Path $SecTempDir "secedit_secreatepagefileprivilege.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeCreatePagefilePrivilege\s*=") {
        $NewLines += "SeCreatePagefilePrivilege = *S-1-5-32-544"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeCreatePagefilePrivilege = *S-1-5-32-544")
    } else {
        $NewLines += "SeCreatePagefilePrivilege = *S-1-5-32-544"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-UraSeCreatePagefilePrivilegeStatus.ps1](../audit_scripts/Get-UraSeCreatePagefilePrivilegeStatus.ps1)

```powershell
# Get-UraSeCreatePagefilePrivilegeStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_secreatepagefileprivilege.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeCreatePagefilePrivilege\s*=\s*(.*)$"
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

## Sources & Compliance References
* **ANSSI Active Directory Hardening Guide**: User Rights Assignment protective controls
* **Microsoft Security Baseline**: User Rights Configuration specifications
