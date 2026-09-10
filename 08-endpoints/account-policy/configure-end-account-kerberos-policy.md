# [REQ-END-165] Account Policy: Kerberos Policy for Endpoints

## Target Scope
* **Applicable Systems**: Tier 2 Client Workstations and Member Servers.
* **Operating Systems**: Windows 10 Enterprise/Professional (1809 and above), Windows 11 Enterprise/Professional (all builds), Windows Server 2016 (and above).

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
* **Supported On**: Windows 10 / Windows 11 / Windows Server 2016 and above
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

Kerberos authentication tokens underpin enterprise access across Active Directory environments. Establishing bounded ticket lifetimes and clock synchronization rules restricts ticket reuse, session hijacking, and replay attacks:

### Technical Threat Vectors and Defense Mechanics
1. **Pass-the-Ticket Mitigation (`MaxTicketAge = 10`, `MaxServiceTicketAge = 600`)**:
   During interactive and network logon sessions, Kerberos Ticket-Granting Tickets (TGTs) and service tickets (TGS) are retained in the LSASS process cache. If an adversary compromises an endpoint, tools like Mimikatz or Rubeus can harvest these tickets to execute Pass-the-Ticket (PtT) lateral movement. Restricting user ticket validity to 10 hours and service tickets to 600 minutes limits the operational lifetime of stolen tokens. Once the ticket expires, the attacker cannot authenticate without the user's ongoing session.
2. **Restricting Unbounded Ticket Renewals (`MaxRenewAge = 7`)**:
   Users can renew Kerberos tickets without re-entering credentials if requested before the ticket expires. Without an enforced upper limit (`MaxRenewAge`), an attacker who steals a renewable TGT could sustain perpetual access by periodically requesting ticket renewals. Capping renewal at 7 days ensures that credentials must be re-evaluated and re-authenticated on a regular basis.
3. **Continuous Logon Rights Enforcement (`TicketValidateClient = 1`)**:
   When `TicketValidateClient` is enabled, the Domain Controller's Key Distribution Center (KDC) validates the client account's logon rights (such as account active status, allowed workstation lists, and logon hours) every time a new service ticket (TGS) is requested. If disabled, a user holding a valid TGT could continue requesting access to file shares, databases, and enterprise services even after their account has been disabled or locked out by IT security.
4. **Anti-Replay Protection via Clock Skew (`MaxClockSkew = 5`)**:
   Kerberos messages include timestamps encrypted with the shared session key. The KDC verifies that the message was generated within the acceptable clock skew window (`MaxClockSkew = 5` minutes). Restricting this tolerance prevents adversaries from capturing authentication packets over the network and replaying them later to gain unauthorized access.
5. **Endpoint Security Posture**:
   Across Tier 2 endpoints and member servers, standardizing Kerberos ticket parameters ensures that lateral movement attempts face tight temporal constraints and strict account revocation enforcement.

---

## Legacy Impact & Compatibility

* **W32Time Synchronization**: All domain members must maintain clock synchronization with Domain Controllers. If an endpoint's clock drifts by more than 5 minutes, Kerberos authentication will fail with error `KRB_AP_ERR_SKEW`. Network firewall rules must permit outbound UDP port 123 to domain time servers.
* **Long-Running Enterprise Services**: Line-of-business applications or scheduled batch jobs that exceed 10 hours should use Group Managed Service Accounts (gMSAs), which automatically manage Kerberos ticket renewal and password rotation.
* **Domain Policy Context**: Kerberos policy parameters are defined at the domain level via the Default Domain Policy; applying these settings locally via security templates ensures baseline alignment during audits and standalone assessments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit the Default Domain Policy (or target GPO linked to workstations/servers).
3. Navigate to:
   `Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Kerberos Policy`
4. Configure the following settings:
   * **Enforce user logon restrictions**: Set to `Enabled`
   * **Maximum lifetime for service ticket**: Set to `600` minutes
   * **Maximum lifetime for user ticket**: Set to `10` hours
   * **Maximum lifetime for user ticket renewal**: Set to `7` days
   * **Maximum tolerance for computer clock synchronization**: Set to `5` minutes
5. Link the GPO and force policy application via `gpupdate /force`.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

[Download Script: Configure-EndAccountKerberosPolicy.ps1](../implementation_scripts/Configure-EndAccountKerberosPolicy.ps1)

```powershell
# Configure-EndAccountKerberosPolicy.ps1
# Description: Configures Kerberos ticket lifetimes, renewal limits, and client validation on Endpoints via SecEdit.

Write-Host "Configuring Endpoint Kerberos policy..." -ForegroundColor Cyan

$SecTempDir = Join-Path $env:TEMP "EndpointKerberosSecTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}

$CfgFile = Join-Path $SecTempDir "end_kerberos.cfg"
$DbFile = Join-Path $SecTempDir "end_kerberos.sdb"
$LogFile = Join-Path $SecTempDir "end_kerberos.log"

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
Write-Host "Endpoint Kerberos policy applied successfully." -ForegroundColor Green
```

*To audit the hardening status:*

[Download Script: Get-EndAccountKerberosPolicyStatus.ps1](../audit_scripts/Get-EndAccountKerberosPolicyStatus.ps1)

```powershell
# Get-EndAccountKerberosPolicyStatus.ps1
# Description: Audits Kerberos ticket policy parameters on Endpoints via SecEdit.

Write-Host "--- Auditing Endpoint Kerberos Policy ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$SecTempDir = Join-Path $env:TEMP "EndpointKerberosAuditTemplate"
if (-not (Test-Path $SecTempDir)) {
    New-Item -Path $SecTempDir -ItemType Directory -Force | Out-Null
}
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

Verify current Kerberos tickets on the client using `klist`:
```cmd
klist
```
Verify that active ticket lifetimes conform to the 10-hour boundary.

To check local domain time synchronization status:
```cmd
w32tm /query /status
```
Confirm that the time source is a valid Domain Controller and local clock offset is within acceptable limits (< 1 second).

---

## Sources & Compliance References
* **CIS Microsoft Windows Server 2022 Benchmark**: Section 1.3.1 (MaxClockSkew <= 5 minutes), Section 1.3.2 (MaxServiceTicketAge <= 600 minutes), Section 1.3.3 (MaxTicketAge <= 10 hours), Section 1.3.4 (MaxRenewAge <= 7 days), Section 1.3.5 (TicketValidateClient = Enabled)
* **CIS Microsoft Windows 10/11 Enterprise Benchmark**: Section 1.3 (Kerberos Policy)
* **DoD Windows Computer STIG**: Rule SV-220710r879610_rule (Kerberos policy settings)
* **ANSSI Active Directory Hardening Guide**: Section 3.4 (Kerberos Authentication Configuration and Ticket Lifetimes)
* **Microsoft Security Baseline Focus**: Domain Security Policy - Kerberos Parameters
* **Related Controls**: [REQ-PAW-154: Account Policy: Kerberos Policy for PAWs](../../07-paws/account-policy/configure-paw-account-kerberos-policy.md), [REQ-DC-002: Kerberos Armoring and FAST Configuration](../../02-domain-controllers/enable-kerberos-armoring.md)
