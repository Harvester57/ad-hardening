# [REQ-PAW-154] Account Policy: Kerberos Policy for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) dedicated to Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1809 and above), Windows 11 Enterprise (all builds).

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy
* **Policy Settings**:
  * Enforce user logon restrictions: `Enabled`
  * Maximum lifetime for service ticket: `600` minutes (10 hours)
  * Maximum lifetime for user ticket: `10` hours
  * Maximum lifetime for user ticket renewal: `7` days
  * Maximum tolerance for computer clock synchronization: `5` minutes
* **Supported On**: Windows 10 Enterprise / Windows 11 Enterprise
* **SecEdit / Security Template Parameters**:
  * `TicketValidateClient` = `1` (Enforces client user right validation on service ticket issuance)
  * `MaxServiceTicketAge` = `600` (Minutes; maximum duration a service ticket remains valid)
  * `MaxTicketAge` = `10` (Hours; maximum duration a Ticket-Granting Ticket [TGT] remains valid)
  * `MaxRenewAge` = `7` (Days; maximum period over which a TGT can be renewed)
  * `MaxClockSkew` = `5` (Minutes; maximum time discrepancy permitted between client and KDC)
* **Vulnerability References**:
  * MITRE ATT&CK: [T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558/), [T1558.001: Golden Ticket](https://attack.mitre.org/techniques/T1558/001/), [T1558.002: Silver Ticket](https://attack.mitre.org/techniques/T1558/002/), [T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/), [T1550.002: Pass the Ticket](https://attack.mitre.org/techniques/T1550/002/)

---

## Rationale

Kerberos is the foundational authentication protocol of Active Directory Domain Services. Ticket lifetimes and synchronization constraints govern the operational window during which authentication tokens remain valid:

### Technical Threat Vectors and Defense Mechanics
1. **Pass-the-Ticket & Credential Replay Window Restriction (`MaxTicketAge = 10`, `MaxServiceTicketAge = 600`)**:
   When an administrator authenticates from a PAW, the Key Distribution Center (KDC) issues a Ticket-Granting Ticket (TGT) and subsequent Ticket-Granting Service (TGS) tickets. These tickets reside in the local LSASS memory space. If an adversary attempts credential theft via Pass-the-Ticket (PtT) or token harvesting, the stolen ticket is valid only for its designated lifespan. Restricting user ticket validity to 10 hours and service tickets to 600 minutes ensures that harvested credentials expire rapidly, severely limiting post-exploitation lateral movement.
2. **Mandatory Renewal Horizon (`MaxRenewAge = 7`)**:
   Kerberos tickets support renewal without re-prompting the user for credentials, provided the renewal request arrives before ticket expiration. Without an upper bound on renewal (`MaxRenewAge`), a long-lived session could be refreshed indefinitely. Capping the renewal threshold at 7 days forces full re-authentication, requiring the administrator to present their smart card / hardware token and verify account credentials.
3. **Live User Rights Validation (`TicketValidateClient = 1`)**:
   When `TicketValidateClient` is enabled, the KDC inspects the user's account status (such as logon hours, workstation restrictions, account disablement, or administrative revocation) each time the client requests a service ticket (TGS). If this setting is disabled, a client holding a valid TGT could continue requesting service tickets and accessing network resources even after their account has been disabled or locked out by an incident responder. Enabling client validation ensures immediate enforcement of directory revocation actions.
4. **Mitigating Replay Attacks via Clock Skew (`MaxClockSkew = 5`)**:
   Kerberos authenticators include encrypted timestamps to prevent attackers from recording authentication packets off the network and replaying them later. The KDC verifies that the authenticator timestamp falls within the allowed clock skew window (`MaxClockSkew = 5` minutes). A tight 5-minute skew tolerance defends against ticket replay while accommodating normal NTP network latency.
5. **Tier 0 PAW Governance**:
   On PAWs, where all directory management operations originate, aligning Kerberos policies prevents stale administrative session reuse and mandates active directory validation.

---

## Legacy Impact & Compatibility

* **Time Synchronization Dependency**: Workstation system clocks must synchronize reliably with the domain hierarchy (PDC emulator via W32Time). If a PAW's clock drifts by more than 5 minutes relative to the domain controller, Kerberos authentication will fail with error `KRB_AP_ERR_SKEW`. Time synchronization over authenticated NTP must be verified.
* **Long-Running Administrative Sessions**: Batch jobs or background scripts that run longer than 10 hours must be architected using Managed Service Accounts (gMSAs) with automatic ticket renewal rather than static administrative user credentials.
* **SecEdit Enforcement**: On domain-joined Windows systems, domain-level Kerberos policies are formally governed by the Default Domain Policy; applying these settings locally via security templates reinforces local compliance and offline evaluation baselines.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy or the target GPO linked to PAWs (e.g., `GPO_Hardening_PAWs`).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy`
4. Configure the following settings:
   * **Enforce user logon restrictions**: Set to `Enabled`
   * **Maximum lifetime for service ticket**: Set to `600` minutes
   * **Maximum lifetime for user ticket**: Set to `10` hours
   * **Maximum lifetime for user ticket renewal**: Set to `7` days
   * **Maximum tolerance for computer clock synchronization**: Set to `5` minutes
5. Link the GPO to the appropriate Organizational Unit and force policy update.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-PawAccountKerberosPolicy.ps1](../implementation_scripts/Configure-PawAccountKerberosPolicy.ps1)

```powershell
# Configure-PawAccountKerberosPolicy.ps1
# Description: Configures Kerberos ticket lifetimes, renewal limits, and client validation on PAWs via SecEdit.

Write-Host "Configuring PAW Kerberos policy..." -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "PAWKerberosSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "paw_kerberos.cfg"
$DbFile = Join-Path $SecTempDir "paw_kerberos.sdb"
$LogFile = Join-Path $SecTempDir "paw_kerberos.log"

$Process = Start-Process secedit -ArgumentList "/export /cfg `"$CfgFile`"" -Wait -NoNewWindow -PassThru
if ($Process.ExitCode -ne 0) {
    Throw "Failed to export current security template."
}

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
        if ($Matches[1] -eq "Kerberos Policy") {
            $InKerb = $true
        } else {
            $InKerb = $false
        }
    }
    if ($InKerb) {
        $IsManaged = $false
        foreach ($Key in $KerbSettings.Keys) {
            if ($Line -match "^\s*$($Key)\s*=") {
                $IsManaged = $true
                break
            }
        }
        if (-not $IsManaged) {
            $NewLines += $Line
        }
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
if ($Proc.ExitCode -ne 0) {
    Throw "Failed to apply SecEdit Kerberos policy."
}

Remove-Item -Path $SecTempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "PAW Kerberos policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-PawAccountKerberosPolicyStatus.ps1](../audit_scripts/Get-PawAccountKerberosPolicyStatus.ps1)

```powershell
# Get-PawAccountKerberosPolicyStatus.ps1
# Description: Audits Kerberos ticket policy parameters on PAWs via SecEdit.

Write-Host "--- Auditing PAW Kerberos Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SecTempDir = Join-Path $env:TEMP "PAWKerberosAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
$CfgFile = Join-Path $SecTempDir "paw_kerberos_audit.cfg"

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
        Write-Host "    [+] $($Key): $Actual (Secure)" -ForegroundColor Green
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

### Option C: Manual Verification

Verify current Kerberos ticket lifetimes on the active session using `klist`:
```cmd
klist
```
Inspect the `Renew Time` and `End Time` of currently cached TGTs to confirm that ticket duration does not exceed 10 hours.

To verify domain controller time synchronization:
```cmd
w32tm /query /status
```
Verify that the `Leap Indicator`, `Stratum`, and clock offset reflect healthy synchronization with the PDC emulator (offset < 1 second).

---

## Sources & Compliance References
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 1.3.1 (MaxClockSkew <= 5 minutes), Section 1.3.2 (MaxServiceTicketAge <= 600 minutes), Section 1.3.3 (MaxTicketAge <= 10 hours), Section 1.3.4 (MaxRenewAge <= 7 days), Section 1.3.5 (TicketValidateClient = Enabled)
* **CIS Microsoft Windows 10/11 Enterprise Benchmark**: Section 1.3 (Kerberos Policy)
* **DoD Windows Computer STIG**: Rule SV-220710r879610_rule (Kerberos policy settings)
* **ANSSI Active Directory Hardening Guide**: Recommendations on Kerberos ticket lifespans, Pass-the-Ticket mitigation, and time synchronization
* **Microsoft Security Baseline Focus**: Domain Security Policy - Kerberos Parameters
* **Related Controls**: [REQ-END-165: Account Policy: Kerberos Policy for Endpoints](../../08-endpoints/account-policy/configure-end-account-kerberos-policy.md), [REQ-DC-002: Kerberos Armoring and FAST Configuration](../../02-domain-controllers/enable-kerberos-armoring.md)
