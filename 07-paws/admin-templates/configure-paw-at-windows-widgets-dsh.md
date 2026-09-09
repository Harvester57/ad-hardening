# [REQ-PAW-195] Administrative Templates: Disable Windows Widgets and News Feed for PAWs

## Target Scope
* **Applicable Systems**: Privileged Access Workstations (PAWs) used for Tier 0 directory administration.
* **Operating Systems**: Windows 10 Enterprise (1607+) and Windows 11 Enterprise.

---

## Implementation Details
* **Priority**: High
* **Policy Category**: Computer Configuration -> Administrative Templates -> Windows Components -> Widgets
* **Policy Name**: Allow widgets
* **Supported On**: Windows 11 (all versions), Windows 10 (version 21H1 and above with News and Interests)
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Dsh`
* **Registry Value**: `AllowNewsAndInterests`
* **Value Type**: `REG_DWORD`
* **Value Data**: `0` (0x00000000 = Suppress widgets and taskbar news feed)
* **Vulnerability References**: MITRE ATT&CK: T1189 (Drive-by Compromise), T1071 (Application Layer Protocol), T1204 (User Execution), T1059 (Command and Scripting Interpreter)

---

## Rationale

Privileged Access Workstations (PAWs) provide the highest level of security isolation for Tier 0 Active Directory administration. They operate under a strict "clean source" principle where only vetted administrative binaries and management consoles are permitted to execute. Windows Widgets and News and Interests dynamically embed web rendering runtimes (Microsoft Edge WebView2) into the taskbar shell, directly violating core PAW security architecture.

### Technical Threat Vectors & Tier 0 Risks
1. **Unacceptable Dynamic Web Rendering on PAWs**: Running a Chromium-based browser rendering engine (`widgets.exe`) directly within an active Tier 0 administrative session exposes the host to web-based code execution vulnerabilities, memory corruption flaws, and DOM-based exploits. Web rendering runtimes must never operate inside an administrative logon session.
2. **Breach of Network Isolation & Egress Policy**: Dedicated PAWs operate in segmented administrative subnets with egress firewalls blocking all general Internet traffic. The Widgets process continuously attempts to establish outbound HTTPS sessions to MSN, Bing, and advertising CDNs (`*.msn.com`, `*.bing.com`), causing constant egress rule violations and flooding security operations center (SOC) log collectors with unauthorized connection attempts.
3. **Third-Party Content Ingestion**: The Widgets framework ingests external news headlines, weather forecasts, and sponsored marketing content from public content distribution networks. Allowing untrusted third-party internet content onto an administrative screen increases the risk of social engineering, accidental clickthroughs, and credential harvesting redirects.
4. **Administrative Host Resource Preservation**: PAW systems require predictable, lightweight operational environments. Terminating unnecessary background web engines frees CPU and RAM resources for administrative operations, PowerShell scripting, and security tooling.

Disabling widgets eliminates the taskbar component entirely and guarantees that the Desktop Shell Host will not initiate network sessions or load web rendering modules.

---

## Legacy Impact & Compatibility

* **Operational Impact**: The Widgets icon and News and Interests feed are completely disabled on PAW workstations. All Tier 0 administrative tooling (Active Directory Administrative Center, MMC, PowerShell, RSAT) functions without impact.
* **User Experience**: Tier 0 administrators work within a clean, austere, and hardened desktop interface without consumer feeds or accidental popup flyouts.
* **Network Impact**: Eliminates unauthorized outbound HTTP/HTTPS traffic to public news, weather, and consumer CDN endpoints.
* **Rollout Recommendations**: Mandatory baseline setting for all PAWs; apply immediately across all administrative host profiles.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to the PAWs Organizational Unit (e.g., `GPO_Hardening_PAW`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Widgets
   ```
4. Double-click **Allow widgets**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the dedicated PAW Organizational Unit and verify policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-PawAtWindowsWidgetsDsh.ps1](../implementation_scripts/Configure-PawAtWindowsWidgetsDsh.ps1)

```powershell
#Configure-PawAtWindowsWidgetsDsh.ps1
# Description: Configures Administrative Templates: Disable Windows Widgets and News Feed for PAWs.

Write-Host "Configuring Administrative Templates: Disable Windows Widgets and News Feed for PAWs..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Widgets and News Feed for PAWs applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-PawAtWindowsWidgetsDshStatus.ps1](../audit_scripts/Get-PawAtWindowsWidgetsDshStatus.ps1)

```powershell
#Get-PawAtWindowsWidgetsDshStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Widgets and News Feed for PAWs.

Write-Host "--- Auditing Administrative Templates: Disable Windows Widgets and News Feed for PAWs ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Dsh"
$ValueName = "AllowNewsAndInterests"
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests
```
Expected output:
```text
AllowNewsAndInterests    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.10.72.1
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Widgets
* **ANSSI Active Directory Hardening Guide**: Section 3.4 - PAW Isolation and Administrative Endpoint Hardening
* **MITRE ATT&CK**: [T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/), [T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/), [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
* **Related Controls**: [REQ-PAW-184: Administrative Templates: Disable Cloud Consumer Account State Content for PAWs](configure-paw-at-cloud-consumer-content.md), [REQ-PAW-175: Administrative Templates: Restrict Internet Communication for PAWs](configure-paw-at-internet-communication.md)
