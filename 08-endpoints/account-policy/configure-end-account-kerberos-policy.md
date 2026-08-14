# [REQ-END-165] Account Policy: Kerberos Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations, Member Servers, Domain Controllers
* **Operating Systems**: Windows 10/11 Enterprise/Professional, Windows Server 2016 (and above)

---

## Implementation Details
* **Priority**: High
* **GPO Path / Registry Location**:
  * **GPO Path**: `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy`
  * **Registry Location / SecEdit Settings**:
    * `TicketValidateClient` = `1` (Enforce user logon restrictions enabled)
    * `MaxServiceTicketAge` = `600` (Maximum lifetime for service ticket = 600 minutes / 10 hours)
    * `MaxTicketAge` = `10` (Maximum lifetime for user ticket = 10 hours)
    * `MaxRenewAge` = `7` (Maximum lifetime for user ticket renewal = 7 days)
    * `MaxClockSkew` = `5` (Maximum tolerance for computer clock synchronization = 5 minutes)

---

## Rationale
Kerberos policy settings define authentication ticket lifetimes and clock tolerance parameters for domain security tokens:
* **Ticket Lifetimes (10h ticket / 600m service)**: Restricting ticket validity limits the operational window for stolen ticket reuse (Pass-the-Ticket / Golden / Silver ticket abuse).
* **Ticket Renewal (7 days)**: Limiting renewable lifetimes requires accounts to periodically re-authenticate.
* **Clock Skew (5 minutes)**: Maintaining tight clock synchronization prevents Kerberos replay attacks.

---

## Legacy Impact & Compatibility
* **Clock Drift**: Workstation system clocks that drift by more than 5 minutes relative to Domain Controllers will fail Kerberos authentication. Time synchronization via NTP/PDC emulator must be maintained.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy.
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy`
4. Configure the settings:
   * **Enforce user logon restrictions**: `Enabled`
   * **Maximum lifetime for service ticket**: `600` minutes
   * **Maximum lifetime for user ticket**: `10` hours
   * **Maximum lifetime for user ticket renewal**: `7` days
   * **Maximum tolerance for computer clock synchronization**: `5` minutes

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountKerberosPolicy.ps1](../implementation_scripts/Configure-EndAccountKerberosPolicy.ps1)

```powershell
# Configure-EndAccountKerberosPolicy.ps1
Write-Host "Configuring Endpoint Kerberos policy..." -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "EndKerberosSecTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }

$CfgFile = Join-Path $SecTempDir "end_kerberos.cfg"
$DbFile = Join-Path $SecTempDir "end_kerberos.sdb"
$LogFile = Join-Path $SecTempDir "end_kerberos.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) { Throw "Failed to export current security template." }

$ConfigText = Get-Content -Path $CfgFile -Raw
if ($ConfigText -notmatch "\[Kerberos Policy\]") {
    $ConfigText += "`r`n[Kerberos Policy]`r`n"
}

$Lines = $ConfigText -split "`r?`n"
$NewLines = @()
$InKerb = $false

$KerbSettings = @{
    "MaxServiceTicketAge"  = 600
    "MaxTicketAge"         = 10
    "MaxRenewAge"          = 7
    "MaxClockSkew"         = 5
    "TicketValidateClient" = 1
}

foreach ($Line in $Lines) {
    if ($Line -match "^\[(.*)\]$") {
        if ($Matches[1] -eq "Kerberos Policy") { $InKerb = $true } else { $InKerb = $false }
    }
    if ($InKerb) {
        $IsManaged = $false
        foreach ($Key in $KerbSettings.Keys) {
            if ($Line -match "^\s*$($Key)\s*=") { $IsManaged = $true; break }
        }
        if (-not $IsManaged) { $NewLines += $Line }
    } else {
        $NewLines += $Line
    }
}

$FinalLines = @()
foreach ($Line in $NewLines) {
    $FinalLines += $Line
    if ($Line -eq "[Kerberos Policy]") {
        foreach ($Key in $KerbSettings.Keys) {
            $Val = $KerbSettings[$Key]
            $FinalLines += "$($Key) = $($Val)"
        }
    }
}

$FinalLines -join "`r`n" | Out-File -FilePath $CfgFile -Encoding ascii -Force
$Proc = Start-Process secedit -ArgumentList "/configure /db `"$DbFile`" /cfg `"$CfgFile`" /areas SECURITYPOLICY /log `"$LogFile`"" -Wait -NoNewWindow -PassThru
if ($Proc.ExitCode -ne 0) { Throw "Failed to apply SecEdit Kerberos policy." }

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Endpoint Kerberos policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountKerberosPolicyStatus.ps1](../audit_scripts/Get-EndAccountKerberosPolicyStatus.ps1)

```powershell
# Get-EndAccountKerberosPolicyStatus.ps1
Write-Host "--- Auditing Endpoint Kerberos Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SecTempDir = Join-Path $env:TEMP "EndKerberosAuditTemplate"
if (-not (Test-Path $SecTempDir)) { New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null }
$CfgFile = Join-Path $SecTempDir "end_kerberos_audit.cfg"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Write-Output "Non-Compliant"
    exit 1
}

$ConfigContent = Get-Content -Path $CfgFile -Raw
Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue

$ExpectedSettings = @{
    "MaxServiceTicketAge"  = 600
    "MaxTicketAge"         = 10
    "MaxRenewAge"          = 7
    "MaxClockSkew"         = 5
    "TicketValidateClient" = 1
}

foreach ($Key in $ExpectedSettings.Keys) {
    $Expected = $ExpectedSettings[$Key]
    if ($ConfigContent -match "(?m)^\s*$($Key)\s*=\s*(.*)\s*$") {
        $Actual = $Matches[1].Trim()
    } else {
        $Actual = ""
    }
    if ($Actual -ne [string]$Expected) {
        Write-Host "    [!] VULNERABLE: $($Key) = '$Actual' (Expected: '$Expected')" -ForegroundColor Red
        $script:Vulnerable = $true
    } else {
        Write-Host "    [+] $($Key): $Actual" -ForegroundColor Green
    }
}

if ($script:Vulnerable) {
    Write-Output "Non-Compliant"
    exit 1
} else {
    Write-Output "Compliant"
    exit 0
}
```

---

## Sources & Compliance References
* **CIS Microsoft Windows Server / Client Benchmark**: Section 1.3 (Kerberos Policy)
* **ANSSI AD Hardening Guide**: Recommendations on Kerberos ticket lifetimes and synchronization constraints
* **DoD Windows Computer STIG**: Kerberos ticket lifetime parameters
