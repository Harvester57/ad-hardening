# [REQ-DC-119] Configure User Rights: Deny log on as a service on Domain Controllers

## Target Scope
* **Applicable Systems**: Domain Controllers (Tier 0 Active Directory infrastructure).
* **Operating Systems**: Windows Server 2016, Windows Server 2019, Windows Server 2022, and Windows Server 2025.

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **Policy Display Name**: `Deny log on as a service`
  * **Privilege Constant**: `SeDenyServiceLogonRight`
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment\Deny log on as a service`
  * **Registry Location**: Stored inside local security database under privilege `SeDenyServiceLogonRight` set to `*S-1-5-32-546 (Guests)`.

---

## Rationale
The `SeDenyServiceLogonRight` explicitly prevents designated accounts from registering and executing as a Windows service process (Logon Type 5). Windows services run unattended in the background under designated security contexts, typically with persistent execution privileges across reboots.

### 1. Technical Threat Vector & Abuse Mechanics
Adversaries who compromise guest accounts or low-privilege service accounts can attempt to install malicious Windows services or alter existing service binaries to run under compromised accounts to establish persistence. Denying service logon rights to untrusted accounts ensures that compromised identities cannot be utilized as service execution vehicles.

### 2. Architectural Defense & Least Privilege Enforcement
Domain Controllers are the root of trust for the entire Active Directory forest, storing the directory database (`ntds.dit`), Kerberos master keys (`krbtgt`), and password hashes for all enterprise identities. Unrestricted allocation of user rights on Domain Controllers introduces devastating forest-compromise risks. Enforcing strict assignment of this privilege ensures that directory synchronization, authentication packages, and system execution remain strictly bounded to authorized directory components and Domain Administrators.

Hardening standards require configuring `SeDenyServiceLogonRight` to include `Guests` (S-1-5-32-546). This ensures guest accounts can never be registered as service logon accounts under any circumstances.

### 3. MITRE ATT&CK Mapping
* **T1543.003 - Create or Modify System Process: Windows Service**
* **T1078.001 - Valid Accounts: Default Accounts**

---

## Legacy Impact & Compatibility
* **Operational Impact**: Denying service logon to `Guests` does not affect standard Windows services or enterprise service accounts. Legitimate services running under `LocalSystem`, `LocalService`, `NetworkService`, or dedicated gMSAs continue to function normally. Failed service initialization attempts are logged under System Event ID 7000 and Security Event ID 4625.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)
1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Navigate to the targeted GPO linked to Tier 0 Domain Controller systems (e.g., `Default Domain Controllers Policy`).
3. In the console tree, browse to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignment`
4. Open the policy **`Deny log on as a service`**.
5. Select the **Define these policy settings** check box.
6. Configure the security principal allocation to: `*S-1-5-32-546 (Guests)`.
7. Click **Apply** and **OK**.
8. Apply and verify policy enforcement across target hosts using `gpupdate /force` and inspect with `secedit /export /cfg C:\Windows\Temp\sec_audit.cfg`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)
[Download Script: Configure-DcUraSeDenyServiceLogonRight.ps1](../implementation_scripts/Configure-DcUraSeDenyServiceLogonRight.ps1)

```powershell
# Configure-DcUraSeDenyServiceLogonRight.ps1
# Configure-DcUraSeDenyServiceLogonRight.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_sedenyservicelogonright.cfg"
$DbFile = Join-Path $SecTempDir "secedit_sedenyservicelogonright.sdb"
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
    if ($InPriv -and $Line -match "^\s*SeDenyServiceLogonRight\s*=") {
        $NewLines += "SeDenyServiceLogonRight = *S-1-5-32-546"
        $KeyAdded = $true
    } else {
        $NewLines += $Line
    }
}

if (-not $KeyAdded) {
    # Find Privilege Rights section index and insert it right after
    $Idx = $NewLines.IndexOf("[Privilege Rights]")
    if ($Idx -ge 0) {
        $NewLines.Insert($Idx + 1, "SeDenyServiceLogonRight = *S-1-5-32-546")
    } else {
        $NewLines += "SeDenyServiceLogonRight = *S-1-5-32-546"
    }
}

$NewLines | Set-Content -Path $CfgFile -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas USER_RIGHTS /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to configure secedit user rights" }
Remove-Item -Path $CfgFile, $DbFile -ErrorAction SilentlyContinue
```

*To audit the hardening status:*
[Download Script: Get-DcUraSeDenyServiceLogonRightStatus.ps1](../audit_scripts/Get-DcUraSeDenyServiceLogonRightStatus.ps1)

```powershell
# Get-DcUraSeDenyServiceLogonRightStatus.ps1
# Get-DcUraSeDenyServiceLogonRightStatus.ps1
$SecTempDir = Join-Path $env:TEMP "SecurityTemplates"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "ura_audit_sedenyservicelogonright.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigText = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $CfgFile -ErrorAction SilentlyContinue

$Match = $ConfigText -match "(?mi)^\s*SeDenyServiceLogonRight\s*=\s*(.*)$"
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
* **CIS Benchmark**: 2.2.20 (L1) Ensure 'Deny log on as a service' includes 'Guests'
* **Microsoft Security Baseline**: User Rights Configuration specifications
* **Microsoft Learn**: User Rights Assignment Reference
