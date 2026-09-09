# [REQ-END-206] Administrative Templates: Disable Windows Widgets and News Feed

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Low
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

Windows Widgets (in Windows 11) and the earlier News and Interests feature (in Windows 10) integrate dynamic cloud-delivered content directly into the Windows desktop taskbar. The feature relies on the Desktop Shell Host (`widgets.exe`) and the Microsoft Edge WebView2 runtime to continuously retrieve and display news feeds, weather reports, sports scores, stock tickers, and third-party sponsored advertisements.

### Technical Threat Vectors & Corporate Risks
1. **Dynamic Web Content Ingestion on the Desktop**: The Widgets infrastructure embeds a full-featured web rendering engine (WebView2/Chromium) directly within the interactive desktop shell. This runtime continuously fetches and renders dynamic HTML, JavaScript, and media assets from public consumer endpoints (`*.msn.com`, `*.bing.com`). Any vulnerability in web content rendering, supply-chain content manipulation on third-party ad networks, or content spoofing exposes the interactive desktop session to malicious drive-by execution.
2. **Persistent Telemetry & Egress Polling**: The widget background service polls Microsoft cloud services continuously to refresh content feeds and transmit interaction metrics. In enterprise environments, this generates substantial telemetry traffic, consumes network bandwidth, and leaks client IP addresses, geo-location data, and user interaction histories to public cloud providers.
3. **Phishing & Social Engineering Vector**: Consumer news feeds prominently display sensationalist headlines, celebrity news, and sponsored partner links directly within the operating system taskbar. Employees clicking these headlines are redirected to external third-party websites, increasing exposure to phishing campaigns, malicious ad redirects (malvertising), and untrusted web domains.
4. **Endpoint Performance & Resource Contention**: The Desktop Shell Host process runs continuously in the background, consuming CPU cycles and substantial RAM to maintain cached web views and feed updates. On virtual desktop infrastructure (VDI) or resource-constrained endpoints, this creates unnecessary overhead.

Disabling widgets eliminates the taskbar icon, suppresses the background rendering processes, and completely halts all associated outbound HTTP/HTTPS feed requests.

---

## Legacy Impact & Compatibility

* **Operational Impact**: The Widgets icon (Windows 11) and News and Interests feed (Windows 10) are permanently removed from the taskbar. Core productivity applications, corporate notifications, Action Center alerts, and enterprise communication tools remain completely unaffected.
* **User Experience**: Users encounter a cleaner taskbar without accidental hover flyouts or distracting news popups during working hours.
* **Network Impact**: Eliminates constant background HTTP/HTTPS polling traffic to MSN and Bing content delivery endpoints.
* **Rollout Recommendations**: Can be deployed across all corporate endpoints immediately; highly recommended across standard desktop fleets and VDI environments.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Widgets
   ```
4. Double-click **Allow widgets**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtWindowsWidgetsDsh.ps1](../implementation_scripts/Configure-EndAtWindowsWidgetsDsh.ps1)

```powershell
#Configure-EndAtWindowsWidgetsDsh.ps1
# Description: Configures Administrative Templates: Disable Windows Widgets and News Feed.

Write-Host "Configuring Administrative Templates: Disable Windows Widgets and News Feed..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Windows Widgets and News Feed applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtWindowsWidgetsDshStatus.ps1](../audit_scripts/Get-EndAtWindowsWidgetsDshStatus.ps1)

```powershell
#Get-EndAtWindowsWidgetsDshStatus.ps1
# Description: Audits Administrative Templates: Disable Windows Widgets and News Feed.

Write-Host "--- Auditing Administrative Templates: Disable Windows Widgets and News Feed ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1189: Drive-by Compromise](https://attack.mitre.org/techniques/T1189/), [T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/), [T1204: User Execution](https://attack.mitre.org/techniques/T1204/)
* **Related Controls**: [REQ-END-195: Administrative Templates: Disable Cloud Consumer Account State Content](configure-end-at-cloud-consumer-content.md), [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md)
