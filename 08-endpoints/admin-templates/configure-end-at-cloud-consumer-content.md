# [REQ-END-195] Administrative Templates: Disable Cloud Consumer Account State Content

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Low
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

Modern editions of Windows integrate consumer-focused features into the desktop shell and operating system menus. These features display dynamic promotional cards, suggestions for Microsoft consumer cloud services (such as personal OneDrive, Microsoft 365 consumer subscriptions, and personal Microsoft Accounts), and personalized application recommendations directly within core UI components like the Start Menu, Settings app, File Explorer, and Lock Screen.

### Technical Threat Vector & Telemetry Leakage
1. **Unwanted Outbound Traffic**: Generating dynamic consumer content requires the Windows desktop shell to make recurring unauthenticated and semi-authenticated HTTP/HTTPS requests to Microsoft Content Delivery Networks (CDNs) and consumer cloud endpoints. In isolated or segmented enterprise environments, these background requests generate noise in perimeter proxy logs and network monitoring systems.
2. **Account Boundary Confusion**: Presenting consumer cloud prompts on enterprise-managed assets encourages end users to associate their personal Microsoft Accounts (MSAs) with corporate domain-joined workstations. This creates an unmanaged data path where corporate information can be inadvertently synchronized to personal OneDrive storage or personal cloud vaults.
3. **Phishing & Social Engineering Vectors**: Dynamic suggestions and third-party promotional banners inside operating system settings can confuse users, conditioning them to accept unexpected prompts or advertisements disguised as official system notifications.
4. **Attack Surface Reduction**: Disabling consumer account state content strips unneeded dynamic web content rendering components from the local shell session, reducing memory footprint and minimizing potential vulnerabilities in web-driven desktop UI modules.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Consumer account recommendation banners, promotional cards, and subscription alerts are completely eliminated from the Settings app and Start menu. Standard domain-joined enterprise operations, Group Policy processing, and corporate Microsoft 365 enterprise sync capabilities remain fully unaffected.
* **User Experience**: Users encounter a cleaner, distraction-free desktop interface focused strictly on corporate applications and local system settings.
* **Network Impact**: Eliminates background HTTPS connections to consumer-facing Microsoft endpoints (such as `*.wns.windows.com` and consumer cloud content servers).
* **Rollout Recommendations**: This policy carries zero risk of breaking enterprise line-of-business (LOB) applications and can be safely deployed fleet-wide without pilot phasing.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\Windows Components\Cloud Content
   ```
4. Double-click **Turn off cloud consumer account state content**.
5. Select **Enabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the appropriate Organizational Unit (OU) and initiate policy replication across all Domain Controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtCloudConsumerContent.ps1](../implementation_scripts/Configure-EndAtCloudConsumerContent.ps1)

```powershell
#Configure-EndAtCloudConsumerContent.ps1
# Description: Configures Administrative Templates: Disable Cloud Consumer Account State Content.

Write-Host "Configuring Administrative Templates: Disable Cloud Consumer Account State Content..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cloud Consumer Account State Content applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtCloudConsumerContentStatus.ps1](../audit_scripts/Get-EndAtCloudConsumerContentStatus.ps1)

```powershell
#Get-EndAtCloudConsumerContentStatus.ps1
# Description: Audits Administrative Templates: Disable Cloud Consumer Account State Content.

Write-Host "--- Auditing Administrative Templates: Disable Cloud Consumer Account State Content ---" -ForegroundColor Cyan
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
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1566: Phishing](https://attack.mitre.org/techniques/T1566/), [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/), [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/)
* **Related Controls**: [REQ-END-205: Administrative Templates: Restrict Windows Store and Appx Execution](configure-end-at-windows-store-restrictions.md), [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md)
