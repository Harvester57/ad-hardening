# [REQ-END-185] Administrative Templates: Disable Cross-Device Experiences

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Cross-Device Experiences
* **Policy Name**: Continue experiences on this device
* **Supported On**: Windows 10 (Version 1703) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Windows\System`
* **Registry Value**: `EnableCdp`
* **Value Type**: `REG_DWORD`
* **Value Data**: `0` (0x00000000 = Cross-Device Experiences / CDP Disabled)
* **Vulnerability References**: MITRE ATT&CK: T1020 (Automated Exfiltration), T1115 (Clipboard Data), T1552 (Unsecured Credentials), T1080 (Taint Shared Content)

---

## Rationale

The Windows Connected Devices Platform (CDP, also known internally as Project Rome) facilitates device-to-device communication, application activity roaming, session continuation ("Continue on PC"), and cross-device clipboard sharing across Windows, iOS, and Android devices. While convenient for consumer multi-device environments, CDP introduces severe security and data-governance vulnerabilities within corporate enterprise networks.

### Technical Threat Vectors & Enterprise Risks
1. **Unmanaged Data Exfiltration & Synchronization**: CDP continuously discovers companion devices using Bluetooth Low Energy (BLE) beacons, local Wi-Fi multicast, and Microsoft cloud relay graphs. When active, CDP synchronizes user activities, document titles, recently visited web URLs, and cloud clipboard contents across all devices linked to the user's Microsoft Account or Azure AD / Entra ID identity. This facilitates inadvertent or malicious exfiltration of sensitive enterprise assets to unmanaged personal devices.
2. **Cross-Boundary Session Hijacking**: If an unmanaged personal phone or laptop sharing the user's identity is infected with malware, an attacker can exploit CDP remote-launch APIs to initiate malicious application commands, push arbitrary web URLs, or interact with services running on the domain-joined workstation without triggering perimeter network detection.
3. **Bypassing Network Boundary Controls**: CDP leverages peer-to-peer Wi-Fi Direct and local subnet broadcast mechanisms, establishing ad-hoc communications channels between systems that bypass corporate firewalls, IDS/IPS sensors, and proxy inspection gateways.
4. **Credential & Token Exposure**: Cloud-synchronized activity histories and clipboard caches may contain sensitive session tokens, temporary passwords, API secrets, or PII copied during day-to-day operations, exposing them to non-compliant cloud repositories and secondary endpoints.

Disabling CDP completely shuts down the Connected Devices Platform User Service (`CDPUserSvc`), suppresses peer discovery broadcasts, and blocks cloud activity synchronization.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Cross-device handoff features (such as sending web pages from mobile browsers to desktop, syncing clipboard history across distinct endpoints, and roaming recent app activities) will be unavailable. Standard local clipboard operations, in-session cut/copy/paste, and managed Remote Desktop (RDP) clipboard redirection remain fully functional.
* **User Experience**: Users cannot link personal mobile devices or unmanaged home PCs to their corporate desktop sessions for task handoff.
* **Network & Firewall Impact**: Reduces local subnet mDNS/UDP discovery traffic and halts outbound connections to Microsoft Project Rome cloud relays.
* **Rollout Recommendations**: High security benefit with negligible impact on core enterprise workflows. Can be deployed broadly across all Tier 2 endpoints following brief communication to users regarding cross-device sync restrictions.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Cross-Device Experiences
   ```
4. Double-click **Continue experiences on this device**.
5. Select **Disabled**.
6. Click **Apply**, then click **OK**.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtCrossDeviceExperiences.ps1](../implementation_scripts/Configure-EndAtCrossDeviceExperiences.ps1)

```powershell
#Configure-EndAtCrossDeviceExperiences.ps1
# Description: Configures Administrative Templates: Disable Cross-Device Experiences.

Write-Host "Configuring Administrative Templates: Disable Cross-Device Experiences..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Cross-Device Experiences applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtCrossDeviceExperiencesStatus.ps1](../audit_scripts/Get-EndAtCrossDeviceExperiencesStatus.ps1)

```powershell
#Get-EndAtCrossDeviceExperiencesStatus.ps1
# Description: Audits Administrative Templates: Disable Cross-Device Experiences.

Write-Host "--- Auditing Administrative Templates: Disable Cross-Device Experiences ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$ValueName = "EnableCdp"
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
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp
```
Expected output:
```text
EnableCdp    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.19.6
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - System / Cross-Device Experiences
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/), [T1115: Clipboard Data](https://attack.mitre.org/techniques/T1115/), [T1552: Unsecured Credentials](https://attack.mitre.org/techniques/T1552/), [T1080: Taint Shared Content](https://attack.mitre.org/techniques/T1080/)
* **Related Controls**: [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md), [REQ-END-196: Administrative Templates: Require PIN Pairing for Connect](configure-end-at-connect-pin-pairing.md)
