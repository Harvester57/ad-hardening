# [REQ-END-190] Administrative Templates: Disable Remote Assistance

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Remote Assistance
* **Policy Name**: Configure Offer Remote Assistance
* **Supported On**: Windows Vista / Windows Server 2008 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`
* **Registry Value**: `fAllowUnsolicited`
* **Value Type**: `REG_DWORD`
* **Value Data**: `0` (0x00000000 = Suppress unsolicited Offer Remote Assistance)
* **Vulnerability References**: MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol), T1113 (Screen Capture), T1219 (Remote Access Software), T1078 (Valid Accounts)

---

## Rationale

Windows Remote Assistance (`msra.exe`) allows support personnel to view or remotely control an active user's desktop session across a network. Remote Assistance supports two primary connection modes: solicited (where an end user creates an encrypted invitation ticket) and unsolicited (where an external operator or administrator initiates an uninvited connection to the target workstation via "Offer Remote Assistance").

### Technical Threat Vectors & Session Shadowing Risks
1. **Unauthorized Session Shadowing & Screen Spying**: Unsolicited Remote Assistance allows members of designated helper security groups to initiate remote desktop viewing sessions without the user actively requesting assistance. If an adversary compromises a helpdesk account, workstation local administrator credential, or support service account, the attacker can leverage unsolicited Remote Assistance to silently view active user desktop sessions, intercept confidential business information, and capture plaintext passwords as users type them into corporate applications.
2. **Interactive Session Seizure & Living-off-the-Land Exploitation**: Remote Assistance provides full interactive keyboard and mouse control options. Attackers can seize control of authenticated enterprise sessions, using the legitimate user's active Kerberos tickets and application permissions to execute unauthorized transactions, access protected shares, or deploy malware under the guise of the logged-on user.
3. **Legacy DCOM & RPC Attack Surface**: Offering Remote Assistance relies on DCOM interfaces (`HNetCfg.FwAuthorizedApplication`, `RasServer.RasServer`) and dynamic high-port RPC endpoints. Exposing these legacy DCOM interfaces across enterprise subnets increases vulnerability to RPC coercion, relay attacks, and lateral movement.
4. **Bypassing Centralized Access Auditing**: Native Windows Remote Assistance lacks granular multi-factor challenge mechanisms, recording, and modern session auditing typically required by enterprise compliance frameworks. Corporate IT support must rely on approved enterprise remote support solutions (with centralized session recording, MFA, and ticketing integration) rather than legacy unsolicited Windows Remote Assistance.

Disabling unsolicited Remote Assistance closes the DCOM listening interfaces and completely blocks inbound uninvited support sessions.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Helpdesk and support technicians cannot use the legacy Windows "Offer Remote Assistance" snap-in. Remote troubleshooting must be performed using approved modern enterprise remote support tooling (e.g., Microsoft Intune Remote Help, Quick Assist with cloud authentication, or centralized privileged access management solutions). Solicited user-initiated Remote Assistance tickets can still be configured if explicitly allowed by policy.
* **User Experience**: Users are protected from unexpected or uninvited remote desktop takeovers and screen monitoring attempts.
* **Network Impact**: Reduces open DCOM/RPC listening ports on client endpoints.
* **Rollout Recommendations**: High security value; deploy across all Tier 2 endpoints in coordination with helpdesk operations.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Remote Assistance
   ```
4. Double-click **Configure Offer Remote Assistance**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtRemoteAssistance.ps1](../implementation_scripts/Configure-EndAtRemoteAssistance.ps1)

```powershell
#Configure-EndAtRemoteAssistance.ps1
# Description: Configures Administrative Templates: Disable Remote Assistance.

Write-Host "Configuring Administrative Templates: Disable Remote Assistance..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Remote Assistance applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtRemoteAssistanceStatus.ps1](../audit_scripts/Get-EndAtRemoteAssistanceStatus.ps1)

```powershell
#Get-EndAtRemoteAssistanceStatus.ps1
# Description: Audits Administrative Templates: Disable Remote Assistance.

Write-Host "--- Auditing Administrative Templates: Disable Remote Assistance ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$ValueName = "fAllowUnsolicited"
$ExpectedValue = 0
if (Test-Path -Path $TargetKey) {
    $Prop = Get-ItemProperty -Path $TargetKey -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -ne $Prop) {
        $Actual = $Prop.$ValueName
        if ($Actual -eq $ExpectedValue) {
            Write-Host "  [+] $ValueName = $($Actual) (Secure)" -ForegroundColor Green
        } else {
            Write-Host "  [!] MISMATCH: $ValueName = $($Actual) (Expected: $($ExpectedValue))" -ForegroundColor Red
            $script:Vulnerable = $true
        }
    } else {
        Write-Host "  [!] MISSING VALUE: $ValueName (Expected: $($ExpectedValue))" -ForegroundColor Red
        $script:Vulnerable = $true
    }
} else {
    Write-Host "  [!] MISSING KEY: $TargetKey" -ForegroundColor Red
    $script:Vulnerable = $true
}

if ($script:Vulnerable) {
    Write-Host "Audit Result: VULNERABLE" -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: SECURE" -ForegroundColor Green
    exit 0
}
```

---

### Option C: Manual Verification

Verify the applied policy setting via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowUnsolicited
```
Expected output:
```text
fAllowUnsolicited    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.35.1
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Remote Assistance
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1021.001: Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/), [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/), [T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* **Related Controls**: [REQ-END-182: Administrative Templates: MSS System and Session Security Protections](configure-end-at-mss-system-protections.md), [REQ-END-188: Administrative Templates: Interactive Logon and Credential Display Options](configure-end-at-logon-display-options.md)
