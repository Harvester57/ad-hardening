# [REQ-PAW-184] Administrative Templates: Disable Cloud Consumer Account State Content for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: Medium
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Cloud Content
* **Policy Name**: Turn off cloud consumer account state content
* **Supported On**: Windows 10 (Version 1703) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
* **Registry Value**: `DisableConsumerAccountStateContent`
* **Value Type**: `REG_DWORD`
* **Value Data**: `1` (0x00000001 = Consumer account state content suppressed)
* **Vulnerability References**: MITRE ATT&CK: T1566 (Phishing), T1078 (Valid Accounts), T1020 (Automated Exfiltration)

---

## Rationale

Privileged Access Workstations (PAWs) are dedicated, single-purpose endpoints reserved exclusively for Tier 0 Active Directory and infrastructure administration. Windows consumer-oriented shell enhancements—such as promotional subscription cards, consumer OneDrive prompts, and personal Microsoft Account (MSA) suggestions—introduce severe architectural and operational risks to high-assurance administrative hosts.

### Technical Threat Vector & PAW Isolation Risks
1. **Air-Gap & Perimeter Violation**: PAWs must operate under strict egress filtering where outbound Internet access is either completely blocked or restricted to authenticated internal admin gateways. Cloud consumer cards make continuous unauthenticated calls to Microsoft consumer CDNs, triggering firewall alarm floods and exposing the PAW to untrusted cloud metadata feeds.
2. **Identity Isolation & Tiering Breach**: Tier 0 administrators must never connect personal identities to management endpoints. Allowing consumer account prompts on a PAW invites accidental or coerced association of personal credentials (e.g., personal Microsoft Accounts), potentially exposing Tier 0 hosts to cloud-based identity compromise or unmonitored consumer OneDrive synchronization.
3. **Shell Hardening & Attack Surface Elimination**: Every dynamic web-backed widget or banner rendered within the Windows Explorer shell or Settings application requires memory resources and relies on HTML/XAML rendering engines. Eliminating consumer content ensures that the administrative desktop remains strictly deterministic, minimal, and secure.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Suppresses all consumer account recommendation banners, promotional tiles, and subscription prompts within the Settings app and Start menu. Tier 0 administrative tooling (RSAT, PowerShell 5.1/7, MMC consoles, and Hyper-V management) is completely unaffected.
* **User Experience**: Administrators receive a lean, distraction-free environment free of consumer clutter and consumer account prompts.
* **Network Impact**: Eliminates background DNS queries and outbound HTTPS connection attempts targeting consumer cloud endpoints (`*.wns.windows.com`, `*.live.com`, `*.microsoft.com`).
* **Rollout Recommendations**: Completely safe to apply across all PAW deployment rings immediately.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content
   ```
4. Double-click **Turn off cloud consumer account state content**.
5. Select **Enabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the dedicated PAW Organizational Unit and initiate policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtCloudConsumerContent.ps1](../implementation_scripts/Configure-PawAtCloudConsumerContent.ps1)

```powershell
#Configure-PawAtCloudConsumerContent.ps1
# Description: Configures Administrative Templates: Disable Cloud Consumer Account State Content for PAWs.

Write-Host "Configuring Administrative Templates: Disable Cloud Consumer Account State Content for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cloud Consumer Account State Content for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtCloudConsumerContentStatus.ps1](../audit_scripts/Get-PawAtCloudConsumerContentStatus.ps1)

```powershell
#Get-PawAtCloudConsumerContentStatus.ps1
# Description: Audits Administrative Templates: Disable Cloud Consumer Account State Content for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Cloud Consumer Account State Content for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$ValueName = "DisableConsumerAccountStateContent"
$ExpectedValue = 1
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerAccountStateContent
```
Expected output:
```text
DisableConsumerAccountStateContent    REG_DWORD    0x1
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.13.1
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Cloud Content Recommendations
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1566: Phishing](https://attack.mitre.org/techniques/T1566/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
* **Related Controls**: [REQ-PAW-194: Administrative Templates: Restrict Windows Store and Appx Execution for PAWs](configure-paw-at-windows-store-restrictions.md), [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md)
