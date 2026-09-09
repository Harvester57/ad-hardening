# [REQ-PAW-179] Administrative Templates: Disable Remote Assistance for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Critical
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

Privileged Access Workstations (PAWs) are dedicated exclusively to managing Tier 0 Active Directory Domain Services, root certificate authorities, and core directory security infrastructure. Permitting any form of Remote Assistance on a PAW constitutes an intolerable security architecture violation that shatters Active Directory administrative tiering.

### Technical Threat Vectors & Tiering Violation Risks
1. **Catastrophic Tiering Breach via Session Shadowing**: In an Active Directory enterprise, helpdesk and IT support technicians operate at Tier 1 or Tier 2. If unsolicited Remote Assistance ("Offer Remote Assistance") is active on a PAW, a compromised Tier 1 helpdesk account or service credential could connect to an active PAW session while a Domain Admin is performing directory tasks. The adversary could shadow the session, harvest Tier 0 credentials from memory or screen display, and seize keyboard control to execute arbitrary code across Domain Controllers.
2. **Elimination of Administrative Session Hijacking**: Tier 0 administrative workflows routinely involve highly privileged PowerShell consoles, Active Directory Administrative Center snap-ins, and disaster recovery procedures. Remote Assistance allows full interactive control over the console, enabling an attacker to manipulate administrative tools in real time under the authenticated context of the Tier 0 operator.
3. **Closing Legacy DCOM and Dynamic RPC Listeners**: Offering Remote Assistance requires endpoints to listen on DCOM interfaces and dynamically assigned RPC high ports. On a hardened PAW, host-based firewalls must enforce strict default-deny rules on all inbound ports. Disabling Remote Assistance eliminates unnecessary DCOM endpoints and prevents RPC coercion and relay attacks.
4. **Enforcing Physical and Clean Source Principles**: PAW troubleshooting and hardware maintenance must occur in person or through dedicated, out-of-band management channels with hardware-enforced isolation. General remote support tooling must never be permitted on administrative bastion hosts.

Disabling unsolicited Remote Assistance ensures that inbound remote assistance requests are unconditionally rejected by the operating system.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Unsolicited Remote Assistance is completely blocked on all PAWs. Standard outbound administrative management connections (such as initiating RDP or PowerShell Remoting from the PAW to Domain Controllers) are completely unaffected.
* **Administrative Impact**: Zero impact on day-to-day Active Directory management.
* **Network Impact**: Eliminates inbound DCOM/RPC listening ports on administrative subnets.
* **Rollout Recommendations**: Mandatory baseline requirement across all PAW systems; deploy immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Remote Assistance
   ```
4. Double-click **Configure Offer Remote Assistance**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtRemoteAssistance.ps1](../implementation_scripts/Configure-PawAtRemoteAssistance.ps1)

```powershell
#Configure-PawAtRemoteAssistance.ps1
# Description: Configures Administrative Templates: Disable Remote Assistance for PAWs.

Write-Host "Configuring Administrative Templates: Disable Remote Assistance for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Remote Assistance for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtRemoteAssistanceStatus.ps1](../audit_scripts/Get-PawAtRemoteAssistanceStatus.ps1)

```powershell
#Get-PawAtRemoteAssistanceStatus.ps1
# Description: Audits Administrative Templates: Disable Remote Assistance for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Remote Assistance for PAWs ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Tiering Enforcement
* **MITRE ATT&CK**: [T1021.001: Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/), [T1113: Screen Capture](https://attack.mitre.org/techniques/T1113/), [T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* **Related Controls**: [REQ-PAW-171: Administrative Templates: MSS System and Session Security Protections for PAWs](configure-paw-at-mss-system-protections.md), [REQ-PAW-177: Administrative Templates: Interactive Logon and Credential Display Options for PAWs](configure-paw-at-logon-display-options.md)
