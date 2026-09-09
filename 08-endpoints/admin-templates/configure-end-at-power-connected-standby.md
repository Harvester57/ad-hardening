# [REQ-END-189] Administrative Templates: Disable Connected Standby Network Connectivity

## Target Scope
* **Applicable Systems**: Tier 2 client workstations and member servers.
* **Operating Systems**: Windows 10 (and above) Enterprise/Professional, Windows Server 2016 (and above).

---

## Implementation Details
* **Priority**: Medium
* **Policy Category**: Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings
* **Policy Settings**:
  * Allow network connectivity during connected-standby (on battery)
  * Allow network connectivity during connected-standby (plugged in)
* **Supported On**: Windows 10 (Version 1607) or Windows Server 2016 and above
* **Registry Key**: `HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9`
* **Registry Values**:
  * `DCSettingIndex` = `0` (REG_DWORD, Disconnect network during standby on battery)
  * `ACSettingIndex` = `0` (REG_DWORD, Disconnect network during standby when plugged in)
* **Vulnerability References**: MITRE ATT&CK: T1200 (Hardware Additions), T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle), T1021 (Remote Services)

---

## Rationale

Modern Standby (S0 Low Power Idle) replaced legacy ACPI S3 (Suspend-to-RAM) sleep states in modern enterprise laptops and convertibles. When "Connected Standby" is permitted, the operating system maintains active Wi-Fi, cellular, and Ethernet network adapters while the display is powered off and the system is suspended. This architecture enables background applications to process incoming push notifications, sync mailboxes, and maintain persistent cloud sockets while unattended.

### Technical Threat Vectors & Sleep-State Exposure
1. **Unattended Attack Surface & Remote Exploitation**: When network interfaces remain energized during sleep states, the Windows TCP/IP stack, SMB client/server, and RPC services continue to process incoming network frames. An attacker on the local network segment can launch port scans, exploit remote code execution vulnerabilities in network services, or attempt network-based credential coercion (e.g., PetitPotam or ShadowCoerce) against a machine whose user is absent and cannot observe malicious activity on the screen.
2. **Untrusted Wi-Fi Association During Transit**: Mobile workers frequently close laptop lids and place systems into transit bags. If connected standby is active, the Wi-Fi adapter remains powered, continuously broadcasting probe requests for remembered enterprise and home SSIDs. In transit hubs (airports, trains, hotels), adversaries operating rogue access points (Evil Twin attacks) or Wi-Fi pineapple devices can force associations, capturing NTLM authentication attempts or injecting unencrypted payloads into background sync streams.
3. **Adversary-in-the-Middle (AiTM) and Session Exposure**: Systems connected to untrusted networks while suspended cannot prompt users for 802.1X certificate validation warnings or captive portal alerts, creating silent opportunities for traffic interception, DNS spoofing, and rogue gateway redirection.
4. **Thermal Throttling and Battery Depletion**: Background network processing in laptop bags frequently causes battery depletion, unexpected wake events, and thermal throttling, degrading hardware lifespan and leaving users without operational battery power in the field.

Disabling network connectivity during connected standby guarantees that the moment the system enters Modern Standby or the display turns off, all network adapters enter a low-power disconnected state (Disconnected Standby), severing all network pathways until the user interactively unlocks the console.

---

## Legacy Impact & Compatibility

* **Operational Impact**: Applications (such as Microsoft Teams, Outlook, and web browsers) will not receive incoming notifications or sync background data while the laptop lid is closed or the device is sleeping. Full synchronization resumes within 1 to 2 seconds upon system wake and user authentication.
* **User Experience**: Substantially improves laptop battery life during sleep and eliminates unwanted fan noise or overheating while carrying devices in bags.
* **Network Impact**: Shuts down sleep-state Wi-Fi probing and eliminates unwanted background telemetry during off-hours.
* **Rollout Recommendations**: Safe for immediate enterprise-wide deployment across all mobile endpoints and laptops.

---

## Implementation Steps

### Option A: Group Policy Object (GPO) Configuration (Preferred)

1. Open the **Group Policy Management Console** (`gpmc.msc`).
2. Edit or create the target GPO linked to workstations and member servers (e.g., `GPO_Hardening_Endpoints`).
3. Navigate to:
   ```text
   Computer Configuration\Policies\Administrative Templates\System\Power Management\Sleep Settings
   ```
4. Double-click **Allow network connectivity during connected-standby (on battery)**:
   * Set to **Disabled**.
5. Double-click **Allow network connectivity during connected-standby (plugged in)**:
   * Set to **Disabled**.
6. Click **Apply**, then click **OK** for both policies.
7. Link the GPO to the appropriate Organizational Unit (OU) and verify policy replication across all domain controllers.

---

### Option B: PowerShell & Registry Configuration (Remediation / Non-GPO)

Run the following script locally to configure the administrative template registry values:

[Download Script: Configure-EndAtPowerConnectedStandby.ps1](../implementation_scripts/Configure-EndAtPowerConnectedStandby.ps1)

```powershell
#Configure-EndAtPowerConnectedStandby.ps1
# Description: Configures Administrative Templates: Disable Connected Standby Network Connectivity.

Write-Host "Configuring Administrative Templates: Disable Connected Standby Network Connectivity..." -ForegroundColor Cyan

if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "DCSettingIndex" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" -Name "ACSettingIndex" -Value 0 -Type DWord -Force

Write-Host "[+] Administrative Templates: Disable Connected Standby Network Connectivity applied successfully." -ForegroundColor Green
```

*To verify the configuration:*

[Download Script: Get-EndAtPowerConnectedStandbyStatus.ps1](../audit_scripts/Get-EndAtPowerConnectedStandbyStatus.ps1)

```powershell
#Get-EndAtPowerConnectedStandbyStatus.ps1
# Description: Audits Administrative Templates: Disable Connected Standby Network Connectivity.

Write-Host "--- Auditing Administrative Templates: Disable Connected Standby Network Connectivity ---" -ForegroundColor Cyan
$script:Vulnerable = $false

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "DCSettingIndex"
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

$TargetKey = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$ValueName = "ACSettingIndex"
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

Verify the applied policy settings via administrative command prompt:
```cmd
reg query "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" /s
```
Expected output:
```text
DCSettingIndex    REG_DWORD    0x0
ACSettingIndex    REG_DWORD    0x0
```

---

## Sources & Compliance References
* **CIS Benchmark**: CIS Microsoft Windows Client Benchmark: Section 18.9.33.6.1, Section 18.9.33.6.2
* **Microsoft Security Baseline**: Windows 10 and Windows 11 Security Baseline - Power Management
* **ANSSI Active Directory Hardening Guide**: Baseline security parameters for managed Windows environments
* **MITRE ATT&CK**: [T1200: Hardware Additions](https://attack.mitre.org/techniques/T1200/), [T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/), [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1021: Remote Services](https://attack.mitre.org/techniques/T1021/)
* **Related Controls**: [REQ-END-186: Administrative Templates: Restrict Internet Communication](configure-end-at-internet-communication.md), [REQ-END-182: Administrative Templates: MSS System and Session Security Protections](configure-end-at-mss-system-protections.md)
